using System.Diagnostics.CodeAnalysis;
using System.Net.Sockets;
using System.Text;

namespace Charon;

/// <summary>Identifies clients by the listener alone: for a socket dedicated to one user.</summary>
/// <remarks>
/// Whoever can connect to the socket is this user, which is decided by what the sandbox makes
/// available.  So there is nothing for the client to prove, or to know.  What it sends is ignored.
/// </remarks>
internal sealed class FixedUserAuthenticator(string userName) : IClientAuthenticator
{
    public bool TryAuthenticate(string? proxyAuthorization, out string? name)
    {
        name = userName;
        return true;
    }
}

/// <summary>Getting paths ready for Kestrel to listen on.</summary>
internal static class UnixSockets
{
    /// <summary>Limit from the size of sun_path in struct sockaddr_un on Linux, less the terminator.</summary>
    public const int MaxPathLength = 107;

    public static bool IsValidPath(string path) =>
        Path.IsPathRooted(path) && Encoding.UTF8.GetByteCount(path) <= MaxPathLength;

    /// <summary>Makes it possible to bind to a path.</summary>
    /// <param name="path">The path of the socket.</param>
    /// <param name="problem">What is in the way, if this returns false.</param>
    /// <remarks>
    /// A socket does not get removed if the process dies, and it then gets in the way of
    /// binding.  Care is needed in removing it: connecting to a regular file gets refused
    /// just like connecting to a stale socket, and a live socket is another instance's.
    /// </remarks>
    public static bool TryPrepare(string path, [NotNullWhen(false)] out string? problem)
    {
        problem = null;
        try
        {
            var directory = Path.GetDirectoryName(path)!;
            if (!OperatingSystem.IsWindows())
                Directory.CreateDirectory(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);

            if (!File.Exists(path))
                return true;

            if (!IsSocket(path))
            {
                problem = "There is a file there that is not a socket.";
                return false;
            }

            using var probe = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
            try
            {
                probe.Connect(new UnixDomainSocketEndPoint(path));
            }
            catch (SocketException e) when (e.SocketErrorCode == SocketError.ConnectionRefused)
            {
                File.Delete(path);
                return true;
            }

            problem = "Something else is listening there.";
            return false;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or SocketException)
        {
            problem = e.Message;
            return false;
        }
    }

    /// <summary>Opening a socket as a file fails, which goes for little else that exists.</summary>
    private static bool IsSocket(string path)
    {
        try
        {
            File.OpenHandle(path).Dispose();
            return false;
        }
        catch (IOException)
        {
            return true;
        }
    }
}
