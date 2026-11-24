using System.Collections.Concurrent;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Charon;

/// <summary>Issues the certificates that clients see when their TLS is intercepted.</summary>
internal sealed class CertificateAuthority
{
    private const int MaxCachedCertificates = 50_000;

    private static readonly TimeSpan LeafLifetime = TimeSpan.FromDays(30);

    /// <summary>How long before its expiry that a certificate gets replaced.</summary>
    private static readonly TimeSpan RenewalMargin = TimeSpan.FromDays(1);

    /// <summary>How long before its expiry that the CA is warned about, as replacing it takes manual work.</summary>
    private static readonly TimeSpan ExpiryWarningPeriod = TimeSpan.FromDays(30);

    private sealed record Leaf(SslStreamCertificateContext Context, DateTimeOffset NotAfter);

    private readonly X509Certificate2 _ca;
    private readonly X509SignatureGenerator _signer;
    private readonly TimeProvider _time;

    /// <summary>
    /// All leaf certificates share one key, as in mitmproxy: generating a key per host
    /// buys nothing, since anything that can read this process's memory has the CA's key.
    /// </summary>
    private readonly ECDsa _leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

    private readonly ConcurrentDictionary<string, Lazy<Leaf>> _leaves = new();

    public X509Certificate2 Certificate => _ca;

    /// <param name="ca">The certificate of the CA, with its private key.</param>
    /// <param name="time">Tells the time, which tests can change.</param>
    public CertificateAuthority(X509Certificate2 ca, TimeProvider? time = null)
    {
        _ca = ca;
        _time = time ?? TimeProvider.System;
        _signer = ca.GetECDsaPrivateKey() is { } ecdsa
            ? X509SignatureGenerator.CreateForECDsa(ecdsa)
            : X509SignatureGenerator.CreateForRSA(
                ca.GetRSAPrivateKey() ?? throw new InvalidOperationException(
                    "The CA certificate has no usable private key."),
                RSASignaturePadding.Pkcs1);
    }

    public static CertificateAuthority LoadOrCreate(string certificateFile, string keyFile)
    {
        if (!File.Exists(certificateFile))
            CreateFiles(certificateFile, keyFile);

        return new CertificateAuthority(X509Certificate2.CreateFromPemFile(certificateFile, keyFile));
    }

    private static void CreateFiles(string certificateFile, string keyFile)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=Charon Proxy CA", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

        var now = DateTimeOffset.UtcNow;
        using var certificate = request.CreateSelfSigned(now.AddDays(-1), now.AddYears(10));

        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(keyFile))!);
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(certificateFile))!);

        // The mode is set on creation so that the key is never readable by anyone else.
        var keyFileOptions = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write };
        if (!OperatingSystem.IsWindows())
            keyFileOptions.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;

        using (var writer = new StreamWriter(keyFile, keyFileOptions))
        {
            writer.Write(key.ExportPkcs8PrivateKeyPem());
        }

        File.WriteAllText(certificateFile, certificate.ExportCertificatePem());
    }

    /// <summary>Logs a warning if the CA has expired, or is going to soon.</summary>
    /// <remarks>
    /// This is not an error, as requests for <c>http://</c> URLs, and the Web UI, still work.
    /// </remarks>
    /// <param name="certificateFile">Where the CA's certificate is, to say in the warning.</param>
    public void WarnOfExpiry(ILogger logger, string certificateFile)
    {
        DateTimeOffset notAfter = _ca.NotAfter;
        var remaining = notAfter - _time.GetUtcNow();

        if (remaining <= TimeSpan.Zero)
        {
            logger.LogWarning("The CA certificate {File} expired at {NotAfter:u}, so clients will refuse to use TLS " +
                              "until it is replaced", certificateFile, notAfter);
        }
        else if (remaining < ExpiryWarningPeriod)
        {
            logger.LogWarning("The CA certificate {File} expires at {NotAfter:u}, after which clients will refuse to use TLS " +
                              "until it is replaced", certificateFile, notAfter);
        }
    }

    /// <summary>Gets a certificate for a host name or IP address.</summary>
    public SslStreamCertificateContext GetCertificate(string host) => GetCertificate(host, [host]);

    /// <summary>Gets one certificate that is for all of the given host names and IP addresses.</summary>
    public SslStreamCertificateContext GetCertificate(string[] hosts) =>
        GetCertificate(string.Join(',', hosts), hosts);   // Commas are not valid in any host.

    private SslStreamCertificateContext GetCertificate(string key, string[] hosts)
    {
        var lazy = _leaves.GetOrAdd(key, static (_, args) => new Lazy<Leaf>(() => args.Self.Issue(args.Hosts)),
                                    (Self: this, Hosts: hosts));

        // Certificates cannot outlast the CA.  One that ends with the CA is kept, even when
        // expired, as a new one would be no better: it would be due for renewal again at once.
        if (lazy.Value.NotAfter - _time.GetUtcNow() < RenewalMargin && lazy.Value.NotAfter < _ca.NotAfter)
        {
            // Only if it is still this one, and not one that another thread has renewed already.
            _leaves.TryRemove(KeyValuePair.Create(key, lazy));
            return GetCertificate(key, hosts);
        }

        // Hosts are chosen by the client, which must not be able to exhaust memory.
        if (_leaves.Count > MaxCachedCertificates)
            _leaves.Clear();

        return lazy.Value.Context;
    }

    private Leaf Issue(string[] hosts)
    {
        var names = new SubjectAlternativeNameBuilder();
        foreach (var host in hosts)
        {
            if (IPAddress.TryParse(host, out var address))
                names.AddIpAddress(address);
            else
                names.AddDnsName(host);
        }

        // Clients go by the subject alternative name, which unlike the
        // common name has no length limit that a long host name could exceed.
        var request = new CertificateRequest(
            new X500DistinguishedName("CN=Charon intercepted"), _leafKey, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(names.Build(critical: true));
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            [new Oid("1.3.6.1.5.5.7.3.1")], false));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        if (_ca.Extensions.OfType<X509SubjectKeyIdentifierExtension>().Any())
            request.CertificateExtensions.Add(
                X509AuthorityKeyIdentifierExtension.CreateFromCertificate(_ca, true, false));

        var now = _time.GetUtcNow();
        var notAfter = now + LeafLifetime;
        if (notAfter > _ca.NotAfter)
            notAfter = _ca.NotAfter;

        // If the CA has expired, still issue a certificate, though it has expired as well:
        // clients can then say what is wrong, when they would otherwise just get disconnected.
        var notBefore = (now < notAfter ? now : notAfter).AddDays(-1);

        var issued = request.Create(
            _ca.SubjectName, _signer, notBefore, notAfter, RandomNumberGenerator.GetBytes(16));

        // offline: without it, .NET would try to fetch OCSP responses from the network.
        var context = SslStreamCertificateContext.Create(
            issued.CopyWithPrivateKey(_leafKey), [_ca], offline: true);

        return new Leaf(context, notAfter);
    }
}
