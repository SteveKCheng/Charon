# Charon

An HTTP(S) forward proxy that allows only whitelisted URLs, for confining AI agents
in sandboxes.  It intercepts TLS like [mitmproxy](https://www.mitmproxy.org/), with
a much narrower scope.  The motivations are in [notes/](notes/).

This is a proof of concept.

## Running

```
dotnet run --project src/Charon -c Release
```

The proxy listens on `127.0.0.1:8080` and the Web UI on `127.0.0.1:8081`.  In the
sandbox, set `http_proxy` and `HTTPS_PROXY`, and have clients trust the CA certificate.
It is generated on first run as `~/.config/charon/ca.crt`, or downloadable from the Web UI.

Settings are the properties of [`CharonOptions`](src/Charon/CharonOptions.cs), which may be
given as environment variables such as `Charon__ProxyPort=8080`, or on the command line.

To carry on with the CA of an existing mitmproxy installation, so that sandboxes need no changes:

```
Charon__CaCertificateFile=$HOME/.mitmproxy/mitmproxy-ca.pem
Charon__CaKeyFile=$HOME/.mitmproxy/mitmproxy-ca.pem
```

## Whitelist

The file `~/.config/charon/whitelist.txt` has the same format as for
[mitmproxy-whitelist](https://github.com/SteveKCheng/mitmproxy-whitelist), and is reloaded
when it changes.  Anything not matched is denied, as is everything if the file is missing.

```
# METHOD: regular expression, matched without regard to case and unanchored
GET: ^https://([-a-z0-9.]+\.)?github\.com/
POST: ^https://github\.com/[^/]+/[^/]+(\.git)?/git-upload-pack$
```

`GET` also covers `HEAD` and `OPTIONS`, `PUT` covers `PATCH` and `DELETE`, and `ANY` is all of these.

Patterns are .NET regular expressions, not PCRE.  Rules starting like the above are indexed
by host name, so that the cost of matching does not grow with the length of the whitelist.
The log says how many rules could not be indexed: these get run against every request.
Write `\.` and not `.` in host names so that rules can be indexed.

## Differences from mitmproxy-whitelist

  - URLs are built from where the request actually goes, not the `Host` header.
    A `Host` header that disagrees with the destination gets the request refused.
  - Tunnels only carry HTTP in TLS.  Anything else, such as SSH over `CONNECT`, is dropped.

## Testing

```
dotnet test
```
