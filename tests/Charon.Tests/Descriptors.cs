using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace Charon.Tests;

/// <summary>Handing over descriptors as systemd does, and finding whether they are still open.</summary>
internal static class Descriptors
{
    /// <summary>
    /// Gives up a descriptor without closing it, as it would be on being passed to a new
    /// process.  What it was is returned, to find whether it is still open later.
    /// </summary>
    public static (int Descriptor, string Target) Release(SafeHandle handle)
    {
        int descriptor = (int)handle.DangerousGetHandle();
        var target = Target(descriptor)!;
        handle.SetHandleAsInvalid();
        return (descriptor, target);
    }

    public static (int Descriptor, string Target) Release(Socket socket)
    {
        // It must not be disposed or finalized after this, as that would never finish.
        GC.SuppressFinalize(socket);
        return Release(socket.SafeHandle);
    }

    public static string? Target(int descriptor) => new FileInfo($"/proc/self/fd/{descriptor}").LinkTarget;

    /// <summary>
    /// Whether anything in this process still refers to what a descriptor was.  Its number
    /// may have been reused, by any test running at the same time, but a socket's inode is not.
    /// </summary>
    public static bool IsOpen(string target) =>
        Directory.EnumerateFileSystemEntries("/proc/self/fd").Any(path =>
        {
            try
            {
                return new FileInfo(path).LinkTarget == target;
            }
            catch (IOException)
            {
                return false;
            }
        });
}
