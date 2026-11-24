using System.Net;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Server.Kestrel.Core;

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
        var certificateNames = ListenAddresses.ParseCertificateNames(options);
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

            // Common services for each invocation of ConfigureProxy
            var idleExit = kestrel.ApplicationServices.GetRequiredService<IdleExit>();
            var defaultAuthenticator = kestrel.ApplicationServices.GetRequiredService<ProxyUserStore>();
            var forwardProxy = kestrel.ApplicationServices.GetRequiredService<ForwardProxy>(); 

            void ConfigureProxy(ListenOptions listen, bool isTls)
            {
                // This setting, which is the default in Kestrel, lets HTTP/1.x and HTTP/2 be
                // accepted in all of Kestrel's connection middleware.
                //
                // Now, Charon's outer proxy connection only accepts HTTP/1.x, since we parse CONNECT requests
                // manually.  To ensure that clients don't try to use HTTP/2 (for the outer connection),
                // ProxyListener.UseTlsToProxy below only offers HTTP/1.x in the TLS negotiation.  In the
                // case of cleartext HTTP/2, Kestrel does not accept that in the first place
                // unless HttpProtocols.Http2 is specified.
                listen.Protocols = HttpProtocols.Http1AndHttp2;

                // Idle-server timeout for proxy connections
                listen.Use(idleExit.Track);

                if (isTls)
                    ProxyListener.UseTlsToProxy(listen, ca, certificateNames);

                ProxyListener.Configure(listen, ca, log, defaultAuthenticator, forwardProxy);
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

            foreach (var (endPoint, isTls) in proxyAddresses)
                Listen(endPoint, isTls ? "proxy over TLS" : "proxy", listen => ConfigureProxy(listen, isTls));

            kestrel.Listen(new UserSocketsEndPoint(), listen => ConfigureProxy(listen, isTls: false));

            void ConfigureUi(ListenOptions listen)
            {
                // Idle-server timeout for Web UI, if enabled
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
        builder.Services.AddSystemdEx();

        if (options.TrafficDatabaseFile.Length > 0)
        {
            builder.Services.AddSingleton(services => new TrafficStore(
                options, services.GetRequiredService<TrafficLog>(), services.GetRequiredService<Whitelist>(),
                services.GetRequiredService<ILoggerFactory>().CreateLogger<TrafficStore>()));
            builder.Services.AddHostedService(services => services.GetRequiredService<TrafficStore>());
        }

        var app = builder.Build();
        app.Lifetime.ApplicationStopping.Register(log.Complete);

        ca.WarnOfExpiry(app.Services.GetRequiredService<ILoggerFactory>().CreateLogger<CertificateAuthority>(),
                        options.CaCertificateFile);

        // There is only one chain for the ASP.NET Core HTTP middleware that applies to all ports.
        // Connections for the proxy are distinguished from non-proxy connections (the Web UI), 
        // by the presence of a ForwardProxy instance as a connection feature.  In turn, this
        // feature is set up by ProxyListener.HandleConnectionAsync when it receives a connection
        // for proxying HTTP requests.
        //
        // We cannot distinguish proxy vs non-proxy connections by host-based routing,
        // since clients of the proxy can write anything in the Host header.
        app.Use(static (context, next) =>
            context.Features.Get<ForwardProxy>() is {} forwardProxy
                ? forwardProxy.ProxyRequestAsync(context) 
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
