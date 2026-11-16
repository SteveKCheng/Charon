using Microsoft.Extensions.Hosting.Systemd;

namespace Charon;

internal static class HostBuilderExtensions
{
    /// <summary>
    /// Add singletons for notifying systemd about service states.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This method differs from <see cref="SystemdHostBuilderExtensions.AddSystemd" />
    /// in that the latter has the wrong heuristic to detect this process is running
    /// as a service of systemd.  Charon may be run under a sandbox without being PID 1,
    /// yet without being a direct child process of systemd.
    /// </para>
    /// <para>
    /// This method checks for the environment variable <c>LISTEN_PID</c>.  It actually
    /// may not exist if socket activation is not being used by systemd.  But the value
    /// of the variable clearly notes the PID of the target service process, which we can match.
    /// </para>
    /// </remarks>
    /// <param name="services">
    /// Builder for the dependency-injection container.
    /// </param>
    public static IServiceCollection AddSystemdEx(this IServiceCollection services)
    {
        if (Environment.OSVersion.Platform != PlatformID.Unix)
            return services;

        if (!int.TryParse(Environment.GetEnvironmentVariable("LISTEN_PID"), out var targetPid) ||
            targetPid != Environment.ProcessId)
            return services;

        services.AddSingleton<ISystemdNotifier, LoggedSystemdNotifier>();
        services.AddSingleton<IHostLifetime, SystemdLifetime>();
        return services;
    }
}

/// <summary>
/// Wrapper around <see cref="SystemdNotifier" /> to log whenever notification are made. 
/// </summary>
internal sealed partial class LoggedSystemdNotifier : ISystemdNotifier
{
    private readonly SystemdNotifier _underlyingNotifier = new();
    private readonly ILogger _logger;

    /// <summary>
    /// Wraps an internally constructed <see cref="SystemdNotifier" /> with logging.
    /// </summary>
    /// <param name="logger">Where the log messages go to. </param>
    public LoggedSystemdNotifier(ILogger<LoggedSystemdNotifier> logger) => _logger = logger;

    public void Notify(ServiceState state)
    {
        if (IsEnabled)
        {
            LogNotification(state.ToString());
            _underlyingNotifier.Notify(state);
        }
    }

    [LoggerMessage(EventId = 0, Level = LogLevel.Information, Message = "Sending systemd notification: {Message}")]
    private partial void LogNotification(string message);

    public bool IsEnabled => _underlyingNotifier.IsEnabled;
}
