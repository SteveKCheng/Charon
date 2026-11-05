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

    private sealed record Leaf(SslStreamCertificateContext Context, DateTimeOffset NotAfter);

    private readonly X509Certificate2 _ca;
    private readonly X509SignatureGenerator _signer;

    /// <summary>
    /// All leaf certificates share one key, as in mitmproxy: generating a key per host
    /// buys nothing, since anything that can read this process's memory has the CA's key.
    /// </summary>
    private readonly ECDsa _leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

    private readonly ConcurrentDictionary<string, Lazy<Leaf>> _leaves = new();

    public X509Certificate2 Certificate => _ca;

    public CertificateAuthority(X509Certificate2 ca)
    {
        _ca = ca;
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

    /// <summary>Gets a certificate for a host name or IP address.</summary>
    public SslStreamCertificateContext GetCertificate(string host)
    {
        var lazy = _leaves.GetOrAdd(host, static (h, self) => new Lazy<Leaf>(() => self.Issue(h)), this);
        if (lazy.Value.NotAfter - DateTimeOffset.UtcNow < TimeSpan.FromDays(1))
        {
            _leaves.TryRemove(host, out _);
            return GetCertificate(host);
        }

        // Hosts are chosen by the client, which must not be able to exhaust memory.
        if (_leaves.Count > MaxCachedCertificates)
            _leaves.Clear();

        return lazy.Value.Context;
    }

    private Leaf Issue(string host)
    {
        var names = new SubjectAlternativeNameBuilder();
        if (IPAddress.TryParse(host, out var address))
            names.AddIpAddress(address);
        else
            names.AddDnsName(host);

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

        var now = DateTimeOffset.UtcNow;
        var notAfter = now + LeafLifetime;
        if (notAfter > _ca.NotAfter)
            notAfter = _ca.NotAfter;

        var issued = request.Create(
            _ca.SubjectName, _signer, now.AddDays(-1), notAfter, RandomNumberGenerator.GetBytes(16));

        // offline: without it, .NET would try to fetch OCSP responses from the network.
        var context = SslStreamCertificateContext.Create(
            issued.CopyWithPrivateKey(_leafKey), [_ca], offline: true);

        return new Leaf(context, notAfter);
    }
}
