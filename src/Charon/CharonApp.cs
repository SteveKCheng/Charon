using System.Net;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;
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

    public static WebApplication Build(WebApplicationBuilder builder, CharonOptions options)
    {
        var ca = CertificateAuthority.LoadOrCreate(options.CaCertificateFile, options.CaKeyFile);
        var log = new TrafficLog(options.TrafficLogCapacity);
        var address = IPAddress.Parse(options.ListenAddress);

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

            kestrel.Listen(address, options.ProxyPort, listen =>
            {
                listen.Protocols = HttpProtocols.Http1AndHttp2;
                ProxyListener.Configure(listen, ca, log, kestrel.ApplicationServices.GetRequiredService<ProxyUserStore>());
            });

            var users = kestrel.ApplicationServices.GetRequiredService<ProxyUserStore>();
            var logger = kestrel.ApplicationServices.GetRequiredService<ILogger<ProxyUserStore>>();
            foreach (var user in users.UsersWithSockets)
            {
                if (!UnixSockets.Prepare(user.Socket!, logger))
                    continue;

                kestrel.ListenUnixSocket(user.Socket!, listen =>
                {
                    listen.Protocols = HttpProtocols.Http1AndHttp2;
                    ProxyListener.Configure(listen, ca, log, new FixedUserAuthenticator(user.Name));
                });
            }

            kestrel.Listen(address, options.UiPort);
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
