using System.Net;
using System.Net.Sockets;
using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Server.Kestrel.Transport.Sockets;

namespace Charon;

/// <summary>Has Kestrel listen on a socket from systemd, in place of binding its address.</summary>
internal sealed class InheritedEndPoint(InheritedSockets.Inherited inherited) : EndPoint
{
    public InheritedSockets.Inherited Inherited => inherited;

    public override AddressFamily AddressFamily => inherited.EndPoint.AddressFamily;

    public override string ToString() => $"{inherited.EndPoint} (from systemd)";
}

/// <summary>Has Kestrel use <see cref="InheritedSocketListener"/> for <see cref="InheritedEndPoint"/>.</summary>
internal sealed class InheritedSocketListenerFactory(ILoggerFactory loggerFactory)
    : IConnectionListenerFactory, IConnectionListenerFactorySelector
{
    public bool CanBind(EndPoint endpoint) => endpoint is InheritedEndPoint;

    public ValueTask<IConnectionListener> BindAsync(EndPoint endpoint, CancellationToken cancellationToken = default) =>
        ValueTask.FromResult<IConnectionListener>(
            new InheritedSocketListener((InheritedEndPoint)endpoint, loggerFactory.CreateLogger<InheritedSocketListener>()));
}

/// <summary>Accepts connections on a socket that is listening already.</summary>
/// <remarks>
/// Kestrel could be given the number of the descriptor instead, but then it and
/// <see cref="InheritedSockets.Inherited.Socket"/> would both close it.  Connections are
/// made by Kestrel's socket transport, as for <see cref="UserSocketListener"/>.
/// </remarks>
internal sealed class InheritedSocketListener(InheritedEndPoint endPoint, ILogger logger) : IConnectionListener
{
    private static readonly TimeSpan AcceptRetryDelay = TimeSpan.FromSeconds(1);

    private readonly Socket _socket = endPoint.Inherited.Socket;
    private readonly SocketConnectionContextFactory _connectionFactory = new(new SocketConnectionFactoryOptions(), logger);

    public EndPoint EndPoint => endPoint;

    public async ValueTask<ConnectionContext?> AcceptAsync(CancellationToken cancellationToken = default)
    {
        while (true)
        {
            try
            {
                var client = await _socket.AcceptAsync(cancellationToken);

                // As Kestrel's own transport does: tunnels would be slowed down otherwise.
                if (client.AddressFamily is AddressFamily.InterNetwork or AddressFamily.InterNetworkV6)
                    client.NoDelay = true;

                return _connectionFactory.Create(client);
            }
            catch (ObjectDisposedException)
            {
                return null;
            }
            catch (SocketException e) when (e.SocketErrorCode == SocketError.OperationAborted)
            {
                return null;
            }
            catch (SocketException e) when (e.SocketErrorCode == SocketError.ConnectionReset)
            {
                // The client gave up while waiting to be accepted.
            }
            catch (SocketException e)
            {
                // Such as having run out of file descriptors.  The socket is still good.
                logger.LogError("Could not accept a connection on {Address}: {Message}", endPoint, e.Message);
                await Task.Delay(AcceptRetryDelay, cancellationToken);
            }
        }
    }

    /// <summary>Closes the socket.  systemd keeps listening, as the socket is its own as well.</summary>
    public ValueTask UnbindAsync(CancellationToken cancellationToken = default)
    {
        _socket.Dispose();
        return ValueTask.CompletedTask;
    }

    public ValueTask DisposeAsync()
    {
        _socket.Dispose();
        _connectionFactory.Dispose();
        return ValueTask.CompletedTask;
    }
}
