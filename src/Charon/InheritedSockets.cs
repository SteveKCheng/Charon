using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace Charon;

/// <summary>
/// Sockets passed by systemd for socket activation, which are listening already, kept by the
/// addresses they are bound to.  Whoever takes one uses it in place of binding that address.
/// </summary>
/// <remarks>
/// Names given in the units are only for messages: what a socket is for is decided by its
/// address, in Charon's own settings.  So a mistake in the units cannot change that.
/// </remarks>
internal sealed class InheritedSockets : IDisposable
{
    /// <summary>The first descriptor passed, after standard input, output and error.</summary>
    public const int FirstDescriptor = 3;

    private const string ListenPid = "LISTEN_PID";
    private const string ListenFds = "LISTEN_FDS";
    private const string ListenFdNames = "LISTEN_FDNAMES";

    // From <sys/socket.h> on Linux.
    private const int SolSocket = 1;
    private const int SoAcceptConn = 30;

    /// <summary>A listening socket from systemd, with what systemd called it.</summary>
    /// <remarks>
    /// The number of its descriptor is not kept: <see cref="Socket"/> owns that, and only
    /// it should close the descriptor.
    /// </remarks>
    public sealed record Inherited(Socket Socket, EndPoint EndPoint, string? Name);

    /// <summary>The sockets not taken yet, by <see cref="ListenAddresses.Key"/>.</summary>
    /// <remarks>
    /// Locked, as sockets are taken both while Kestrel starts and by the sockets of
    /// users, which follow changes to their file.
    /// </remarks>
    private readonly Dictionary<string, Inherited> _sockets = new();
    private readonly Lock _lock = new();
    private readonly ILogger _logger;

    public static InheritedSockets None(ILogger logger) => new([], [], logger);

    /// <summary>
    /// Takes what systemd passed to this process, as <c>sd_listen_fds(3)</c> does, and
    /// unsets the variables that say so, which are not meant for any other process.
    /// </summary>
    /// <remarks>
    /// Variables are unset only for .NET, which is what starts any other processes.
    /// </remarks>
    public static InheritedSockets FromEnvironment(ILogger logger)
    {
        var listenPid = Environment.GetEnvironmentVariable(ListenPid);
        var listenFds = Environment.GetEnvironmentVariable(ListenFds);
        var listenFdNames = Environment.GetEnvironmentVariable(ListenFdNames);
        Environment.SetEnvironmentVariable(ListenPid, null);
        Environment.SetEnvironmentVariable(ListenFds, null);
        Environment.SetEnvironmentVariable(ListenFdNames, null);

        if (!OperatingSystem.IsLinux())
            return None(logger);

        var count = CountPassed(listenPid, listenFds, Environment.ProcessId, out var problem);
        if (problem is not null)
            logger.LogWarning("Not using the sockets from systemd: {Problem}", problem);

        return new(Enumerable.Range(FirstDescriptor, count).ToArray(), listenFdNames?.Split(':') ?? [], logger);
    }

    /// <summary>How many descriptors were passed, going by the variables from systemd.</summary>
    /// <param name="problem">Why the variables cannot be believed, if they were set at all.</param>
    internal static int CountPassed(string? listenPid, string? listenFds, int processId, out string? problem)
    {
        problem = null;
        if (listenFds is null)
            return 0;

        // Meant for another process, which left them for its children by mistake.
        if (!int.TryParse(listenPid, NumberStyles.None, CultureInfo.InvariantCulture, out var pid) || pid != processId)
            return 0;

        if (!int.TryParse(listenFds, NumberStyles.None, CultureInfo.InvariantCulture, out var count) ||
            count > int.MaxValue - FirstDescriptor)
        {
            problem = $"{ListenFds} is \"{listenFds}\", which is not a number of descriptors.";
            return 0;
        }

        return count;
    }

    /// <summary>Takes ownership of descriptors, closing the ones that cannot be listened on.</summary>
    /// <param name="descriptors">Descriptors that are this process's own to close.</param>
    /// <param name="names">Names for the descriptors in the same order, which may be missing.</param>
    internal InheritedSockets(IReadOnlyList<int> descriptors, IReadOnlyList<string> names, ILogger logger)
    {
        _logger = logger;
        for (int i = 0; i < descriptors.Count; i++)
        {
            var name = i < names.Count && names[i].Length > 0 ? names[i] : null;
            if (Adopt(descriptors[i], name, out var problem) is { } inherited)
            {
                _logger.LogInformation("systemd passed a socket on {Address}, as descriptor {Descriptor} ({Name})",
                                       inherited.EndPoint, descriptors[i], name ?? "with no name");
            }
            else
            {
                _logger.LogWarning("Closing descriptor {Descriptor} ({Name}) passed by systemd: {Problem}",
                                   descriptors[i], name ?? "with no name", problem);
            }
        }
    }

    /// <summary>Takes ownership of a descriptor, to be kept if it can be listened on.</summary>
    private Inherited? Adopt(int descriptor, string? name, out string? problem)
    {
        var handle = new SafeSocketHandle(descriptor, ownsHandle: true);
        Socket socket;
        try
        {
            socket = new Socket(handle);
        }
        catch (SocketException e)
        {
            handle.Dispose();
            problem = $"It is not a socket: {e.Message}";
            return null;
        }

        problem = Check(socket);
        if (problem is null)
        {
            var endPoint = socket.LocalEndPoint!;
            var inherited = new Inherited(socket, endPoint, name);
            if (_sockets.TryAdd(ListenAddresses.Key(endPoint), inherited))
                return inherited;
            problem = $"Another socket passed is on {endPoint} already.";
        }

        socket.Dispose();
        return null;
    }

    /// <summary>Why a socket cannot be listened on, or null if it can.</summary>
    private static string? Check(Socket socket)
    {
        // .NET does not refuse other kinds of files, but the system does.
        var acceptConn = new byte[sizeof(int)];
        try
        {
            socket.GetRawSocketOption(SolSocket, SoAcceptConn, acceptConn);
        }
        catch (SocketException e)
        {
            return $"It is not a socket: {e.Message}";
        }

        if (socket.SocketType != SocketType.Stream)
            return $"It is a socket of type {socket.SocketType}, not a stream.";

        if (socket.AddressFamily is not (AddressFamily.InterNetwork or AddressFamily.InterNetworkV6 or AddressFamily.Unix))
            return $"It is a socket of family {socket.AddressFamily}.";

        // Accept=yes in the unit passes a connection instead of a listening socket.
        if (BitConverter.ToInt32(acceptConn) == 0)
            return "It is not listening, as it would be with Accept=no in the unit.";

        return socket.LocalEndPoint switch
        {
            IPEndPoint => null,
            UnixDomainSocketEndPoint unix when unix.ToString()!.StartsWith('/') => null,
            var other => $"It is bound to \"{other}\", which is not an address that Charon can listen on.",
        };
    }

    /// <summary>Takes the socket on an address, which the caller is then to close.</summary>
    public bool TryTake(EndPoint endPoint, [NotNullWhen(true)] out Inherited? inherited)
    {
        lock (_lock)
            return _sockets.Remove(ListenAddresses.Key(endPoint), out inherited);
    }

    /// <summary>Sockets that have not been taken, as they are now.</summary>
    public Inherited[] Remaining
    {
        get
        {
            lock (_lock)
                return _sockets.Values.ToArray();
        }
    }

    /// <summary>Closes the sockets that were not taken.  systemd keeps them open, as they are its own.</summary>
    public void Dispose()
    {
        lock (_lock)
        {
            foreach (var inherited in _sockets.Values)
                inherited.Socket.Dispose();
            _sockets.Clear();
        }
    }
}
