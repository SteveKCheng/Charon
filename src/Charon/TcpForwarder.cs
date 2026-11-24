using System.IO.Pipelines;
using System.Net;
using System.Net.Sockets;
using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Connections.Features;

namespace Charon;

/// <summary>
/// Forwards the data of CONNECT tunnels as it is, to targets that the whitelist allows that for.
/// </summary>
/// <remarks>
/// <para>
/// Whether a tunnel is forwarded this way depends only on its target, and never on the data in it.
/// Looking at the data for what protocol it is would not work when the server speaks first,
/// as in SSH, since the client may send nothing until then.
/// </para>
/// <para>
/// The whitelist is consulted once, as the tunnel is opened.  Tunnels that are open stay open if the
/// rule, or the user, is removed.
/// </para>
/// </remarks>
internal sealed class TcpForwarder(Whitelist whitelist, TrafficLog log, CharonOptions options,
                                   IHostApplicationLifetime lifetime)
{
    private const int BufferSize = 64 * 1024;

    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(15);

    private static readonly ReadOnlyMemory<byte> NotImplemented =
        "HTTP/1.1 501 Not Implemented\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"u8.ToArray();

    private static readonly ReadOnlyMemory<byte> BadGateway =
        "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"u8.ToArray();

    private static readonly ReadOnlyMemory<byte> GatewayTimeout =
        "HTTP/1.1 504 Gateway Timeout\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"u8.ToArray();

    /// <summary>The form of a target that rules are matched against, in which there is always a port.</summary>
    private static string GetUrl(Authority target) => $"tcp://{target.UrlHost}:{target.Port}/";

    /// <summary>Decides if a tunnel may carry any data at all to its target.</summary>
    public WhitelistDecision Evaluate(Authority target) =>
        whitelist.Evaluate(Capability.Tcp, GetUrl(target), target.Host);

    /// <summary>
    /// Connects to the target of a tunnel, responds to the CONNECT request, and
    /// forwards data until the tunnel is closed.
    /// </summary>
    /// <param name="connection">The client's connection, past its CONNECT request.</param>
    /// <param name="target">Where the tunnel goes.</param>
    /// <param name="userName">The proxy's user, or null for the anonymous user.</param>
    /// <param name="rule">The rule that allows the tunnel.</param>
    /// <param name="whitelistHash">Identifies the whitelist that has the rule.</param>
    /// <param name="established">The response to the CONNECT request for when it succeeds.</param>
    public async Task ForwardAsync(ConnectionContext connection, Authority target, string? userName,
                                   WhitelistRule rule, string whitelistHash, ReadOnlyMemory<byte> established)
    {
        var entry = log.Add(ListenAddresses.NameOfClient(connection.RemoteEndPoint), "CONNECT", GetUrl(target),
                            allowed: true, ruleLine: rule.Line, rule: rule.Text, whitelist: whitelistHash, user: userName);

        void Finish(int status, string note) => log.Update(entry with
        {
            Status = status,
            DurationMs = (DateTimeOffset.UtcNow - entry.Time).TotalMilliseconds,
            Note = note,
        });

        // Connecting directly would bypass that proxy, which may well be there as a restriction.
        if (options.UpstreamProxy is not null)
        {
            Finish(StatusCodes.Status501NotImplemented, "TCP tunnels do not work with UpstreamProxy");
            await connection.Transport.Output.WriteAsync(NotImplemented);
            return;
        }

        // The client hears of success only once there is a connection, so that it can tell failures apart.
        Socket? upstream = null;
        int failure = StatusCodes.Status502BadGateway;
        string problem = "";
        try
        {
            upstream = await ConnectAsync(target, lifetime.ApplicationStopping);
        }
        catch (SocketException e)
        {
            problem = $"Could not connect: {e.SocketErrorCode}";
        }
        catch (OperationCanceledException) when (lifetime.ApplicationStopping.IsCancellationRequested)
        {
            problem = "Stopping";
        }
        catch (OperationCanceledException)
        {
            failure = StatusCodes.Status504GatewayTimeout;
            problem = "Could not connect: timed out";
        }

        if (upstream is null)
        {
            Finish(failure, problem);
            await connection.Transport.Output.WriteAsync(
                failure == StatusCodes.Status504GatewayTimeout ? GatewayTimeout : BadGateway);
            return;
        }

        using (upstream)
        {
            if (connection.Features.Get<IConnectionSocketFeature>()?.Socket is { AddressFamily: not AddressFamily.Unix } client)
                EnableKeepAlive(client);

            var relay = new Relay(connection, upstream, options.ActivityTimeout);
            string? error = null;
            try
            {
                await connection.Transport.Output.WriteAsync(established);
                error = await relay.RunAsync(lifetime.ApplicationStopping);
            }
            catch (Exception e) when (e is IOException or InvalidOperationException)
            {
                error = "Client disconnected";    // Before it could get the response.
            }
            finally
            {
                var amounts = $"{relay.BytesSent} bytes sent, {relay.BytesReceived} bytes received";
                Finish(StatusCodes.Status200OK, error is null ? amounts : $"{error}; {amounts}");
            }
        }
    }

    private static async Task<Socket> ConnectAsync(Authority target, CancellationToken stopping)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(stopping);
        timeout.CancelAfter(ConnectTimeout);

        // For both IPv4 and IPv6, trying all of the addresses that the host has.
        var socket = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        try
        {
            await socket.ConnectAsync(new DnsEndPoint(target.Host, target.Port), timeout.Token);
            EnableKeepAlive(socket);
            return socket;
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Has a connection be found out if the other end is gone.  There is no timeout for
    /// tunnels that are idle, so otherwise, it could stay open forever.
    /// </summary>
    private static void EnableKeepAlive(Socket socket)
    {
        try
        {
            socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
            socket.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveTime, 60);
            socket.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveInterval, 15);
        }
        catch (Exception e) when (e is SocketException or ObjectDisposedException)
        {
            // The connection has been closed already, which will be noticed when it is used.
        }
    }

    /// <summary>One tunnel that is open.</summary>
    /// <param name="closingTimeout">
    /// How long the server may be silent once the client has finished sending.  The client may have
    /// gone away altogether, which looks no different until there is something to send to it.
    /// </param>
    private sealed class Relay(ConnectionContext connection, Socket upstream, TimeSpan closingTimeout)
    {
        private bool _clientFinished;

        public long BytesSent { get; private set; }
        public long BytesReceived { get; private set; }

        /// <summary>Forwards data in both directions.</summary>
        /// <returns>What went wrong, or null if the tunnel was closed in an orderly way.</returns>
        public async Task<string?> RunAsync(CancellationToken stopping)
        {
            using var cancel = CancellationTokenSource.CreateLinkedTokenSource(stopping);
            using var receiveTimeout = CancellationTokenSource.CreateLinkedTokenSource(cancel.Token);

            var sending = SendAsync(receiveTimeout, cancel.Token);
            var receiving = ReceiveAsync(receiveTimeout);

            // The client finishing does not end the tunnel, as the response may be still to come.
            // The server finishing does: Kestrel cannot close only one direction to the client.
            var error = await await Task.WhenAny(receiving, FailureOf(sending, receiving));

            cancel.Cancel();
            await Task.WhenAll(sending, receiving);

            if (stopping.IsCancellationRequested)
                error = "Stopping";

            // So that the client does not take data that got cut off to be complete.
            if (error is not null)
                connection.Abort(new ConnectionAbortedException(error));

            return error;
        }

        /// <summary>Waits for an error in sending, and for receiving if there is none.</summary>
        private static async Task<string?> FailureOf(Task<string?> sending, Task<string?> receiving) =>
            await sending ?? await receiving;

        private async Task<string?> SendAsync(CancellationTokenSource receiveTimeout, CancellationToken cancellationToken)
        {
            var input = connection.Transport.Input;
            while (true)
            {
                ReadResult result;
                try
                {
                    result = await input.ReadAsync(cancellationToken);
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    return null;
                }
                catch (Exception e) when (e is IOException or OperationCanceledException or InvalidOperationException)
                {
                    return "Client disconnected";
                }

                try
                {
                    foreach (var segment in result.Buffer)
                    {
                        for (var rest = segment; !rest.IsEmpty;)
                        {
                            int count = await upstream.SendAsync(rest, cancellationToken);
                            BytesSent += count;
                            rest = rest[count..];
                        }
                    }

                    if (result.IsCompleted)
                    {
                        upstream.Shutdown(SocketShutdown.Send);
                        _clientFinished = true;
                        receiveTimeout.CancelAfter(closingTimeout);
                        return null;
                    }
                }
                catch (OperationCanceledException)
                {
                    return null;
                }
                catch (Exception e) when (e is SocketException or ObjectDisposedException)
                {
                    return $"Server disconnected: {(e as SocketException)?.SocketErrorCode}";
                }
                finally
                {
                    input.AdvanceTo(result.Buffer.End);
                }
            }
        }

        private async Task<string?> ReceiveAsync(CancellationTokenSource timeout)
        {
            var output = connection.Transport.Output;
            var cancellationToken = timeout.Token;
            while (true)
            {
                int count;
                try
                {
                    count = await upstream.ReceiveAsync(output.GetMemory(BufferSize), cancellationToken);
                }
                catch (OperationCanceledException)
                {
                    // If it is not the timeout then this is because of something else, reported elsewhere.
                    return _clientFinished ? "Timed out waiting for the server to finish" : null;
                }
                catch (Exception e) when (e is SocketException or ObjectDisposedException)
                {
                    return $"Server disconnected: {(e as SocketException)?.SocketErrorCode}";
                }

                if (count == 0)
                    return null;

                try
                {
                    output.Advance(count);
                    BytesReceived += count;

                    // This waits for a client that is slow to take the data.
                    var result = await output.FlushAsync(cancellationToken);
                    if (result.IsCompleted)
                        return "Client disconnected";
                }
                catch (OperationCanceledException)
                {
                    return _clientFinished ? "Timed out waiting for the client to take data" : null;
                }
                catch (Exception e) when (e is IOException or InvalidOperationException)
                {
                    return "Client disconnected";
                }

                if (_clientFinished)
                    timeout.CancelAfter(closingTimeout);
            }
        }
    }
}
