using System.Net;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Connections.Features;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Yarp.ReverseProxy.Forwarder;

namespace Charon;

/// <summary>Assembles the proxy and its Web UI, which share a process but not a port.</summary>
public static class CharonApp
{
    /// <summary>
    /// The version of this build, to tell it apart from others.  Uncommitted changes are
    /// noted since otherwise, the version would be that of the commit they are based on.
    /// </summary>
    internal static string Version { get; } =
        $"{GitVersionInformation.SemVer}+{GitVersionInformation.ShortSha}" +
        (GitVersionInformation.UncommittedChanges == "0" ? "" : ".modified");

    public static WebApplication Build(WebApplicationBuilder builder, CharonOptions options) =>
        Build(builder, options, InheritedSockets.FromEnvironment);

    /// <param name="inheritSockets">Gets the sockets passed for socket activation.</param>
    internal static WebApplication Build(WebApplicationBuilder builder, CharonOptions options,
                                         Func<ILogger, InheritedSockets> inheritSockets)
    {
        var ca = CertificateAuthority.LoadOrCreate(options.CaCertificateFile, options.CaKeyFile);
        var log = new TrafficLog(options.TrafficLogCapacity);
        var (proxyAddresses, uiAddresses) = ListenAddresses.ParseSettings(options);
        if (options.IdleTimeout <= TimeSpan.Zero)
            throw new InvalidOperationException("The setting IdleTimeout must be more than 0, or not set for never stopping.");

        builder.WebHost.ConfigureKestrel(kestrel =>
        {
            // Kestrel's defaults suit a server protecting itself from the
            // Internet, and would break large uploads and slow streams passing through.
            kestrel.AddServerHeader = false;
            kestrel.Limits.MaxRequestBodySize = null;
            kestrel.Limits.MinRequestBodyDataRate = null;
            kestrel.Limits.MinResponseDataRate = null;
            kestrel.Limits.MaxRequestHeadersTotalSize = 256 * 1024;
            kestrel.Limits.MaxRequestLineSize = 64 * 1024;
            kestrel.Limits.Http2.MaxRequestHeaderFieldSize = 64 * 1024;

            var idleExit = kestrel.ApplicationServices.GetRequiredService<IdleExit>();

            void ConfigureProxy(ListenOptions listen)
            {
                listen.Protocols = HttpProtocols.Http1AndHttp2;

                // First, so that it counts tunnels as well, for as long as they are open.
                listen.Use(idleExit.Track);
                ProxyListener.Configure(listen, ca, log, kestrel.ApplicationServices.GetRequiredService<ProxyUserStore>());
            }

            var inherited = kestrel.ApplicationServices.GetRequiredService<InheritedSockets>();
            var logger = kestrel.ApplicationServices.GetRequiredService<ILoggerFactory>().CreateLogger(typeof(CharonApp));

            // A socket from systemd is used if it is on an address that would be listened on anyway.
            void Listen(EndPoint endPoint, string role, Action<ListenOptions> configure)
            {
                if (inherited.TryTake(endPoint, out var socket))
                {
                    kestrel.Listen(new InheritedEndPoint(socket), configure);
                    logger.LogInformation("Listening on {Address} for the {Role}, with the socket from systemd", endPoint, role);
                    return;
                }

                ListenAddresses.Listen(kestrel, endPoint, configure);
                if (inherited.IsActivated)
                {
                    logger.LogWarning("Listening on {Address} for the {Role}, but systemd did not pass a socket for it, " +
                                      "so connecting to it will not start Charon", endPoint, role);
                }
                else
                {
                    logger.LogInformation("Listening on {Address} for the {Role}", endPoint, role);
                }
            }

            foreach (var endPoint in proxyAddresses)
                Listen(endPoint, "proxy", ConfigureProxy);

            kestrel.Listen(new UserSocketsEndPoint(), ConfigureProxy);

            void ConfigureUi(ListenOptions listen)
            {
                if (options.IdleTimeoutCountsWebUI)
                    listen.Use(idleExit.Track);
            }

            foreach (var endPoint in uiAddresses)
                Listen(endPoint, "Web UI", ConfigureUi);
        });

        // These log a few lines for every request, which is what the Web UI is for.
        builder.Logging.AddFilter("Microsoft.AspNetCore", LogLevel.Warning);
        builder.Logging.AddFilter("Yarp", LogLevel.Warning);

        builder.Services.AddHttpForwarder();
        builder.Services.AddSingleton(options);
        builder.Services.AddSingleton(log);
        builder.Services.AddSingleton(services => new Whitelist(
            options.WhitelistFile, services.GetRequiredService<ILoggerFactory>().CreateLogger<Whitelist>()));
        builder.Services.AddSingleton(_ => ForwardProxy.CreateUpstreamClient(options));
        builder.Services.AddSingleton(services => new CredentialStore(
            options.CredentialsFile, services.GetRequiredService<HttpMessageInvoker>(),
            services.GetRequiredService<ILoggerFactory>().CreateLogger<CredentialStore>()));
        builder.Services.AddSingleton(services => new ProxyUserStore(
            options.ProxyUsersFile, options.RequireProxyAuthentication, services.GetRequiredService<CredentialStore>(),
            services.GetRequiredService<ILoggerFactory>().CreateLogger<ProxyUserStore>()));
        builder.Services.AddSingleton<ForwardProxy>();
        builder.Services.AddSingleton<IConnectionListenerFactory, UserSocketListenerFactory>();
        builder.Services.AddSingleton<IConnectionListenerFactory, InheritedSocketListenerFactory>();
        builder.Services.AddSingleton<IdleExit>();
        builder.Services.AddHostedService(services => services.GetRequiredService<IdleExit>());
        builder.Services.AddSingleton(services =>
            inheritSockets(services.GetRequiredService<ILoggerFactory>().CreateLogger<InheritedSockets>()));
        builder.Services.ConfigureHttpJsonOptions(o =>
            o.SerializerOptions.TypeInfoResolverChain.Insert(0, CharonAppJsonContext.Default));

        if (options.TrafficDatabaseFile.Length > 0)
        {
            builder.Services.AddSingleton(services => new TrafficStore(
                options, services.GetRequiredService<TrafficLog>(), services.GetRequiredService<Whitelist>(),
                services.GetRequiredService<ILoggerFactory>().CreateLogger<TrafficStore>()));
            builder.Services.AddHostedService(services => services.GetRequiredService<TrafficStore>());
        }

        var app = builder.Build();
        app.Lifetime.ApplicationStopping.Register(log.Complete);
        var proxy = app.Services.GetRequiredService<ForwardProxy>();

        // Which listener accepted the connection decides who it talks to.  Host-based routing
        // would be no good: clients of the proxy can write anything in the Host header.
        app.Use((context, next) =>
            context.Features.Get<IConnectionItemsFeature>()?.Items.ContainsKey(typeof(ProxyListener)) == true
                ? proxy.HandleAsync(context)
                : next(context));

        app.MapGet("/", async context =>
        {
            context.Response.ContentType = "text/html; charset=utf-8";

            // URLs on this page come from sandboxed clients and so are hostile input.
            context.Response.Headers.ContentSecurityPolicy =
                "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'";

            using var page = Assembly.GetExecutingAssembly().GetManifestResourceStream("index.html")!;
            await page.CopyToAsync(context.Response.Body);
        });

        app.MapGet("/api/traffic", (TrafficLog log, CancellationToken cancellationToken) =>
            TypedResults.ServerSentEvents(log.SubscribeAsync(cancellationToken)));

        app.MapGet("/api/status", (IServiceProvider services) =>
            Results.Json(new StatusMessage()
                {
                    Version = Version,
                    TrafficDatabase = services.GetService<TrafficStore>()?.Status
                },
                CharonAppJsonContext.Default.StatusMessage));

        app.MapGet("/ca.crt", () =>
            Results.Text(ca.Certificate.ExportCertificatePem(), "application/x-pem-file"));

        return app;
    }

    internal sealed class StatusMessage
    {
        public required string Version { get; set; }

        public TrafficStoreStatus? TrafficDatabase { get; set; }
    }
}

[JsonSourceGenerationOptions(JsonSerializerDefaults.Web)]
[JsonSerializable(typeof(CharonApp.StatusMessage))]
[JsonSerializable(typeof(TrafficEntry))]
internal partial class CharonAppJsonContext : JsonSerializerContext
{
}
