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

Two more types of rule are for what those deliberately do not grant, and `ANY` does not include them:

```
# GET, HEAD or OPTIONS requests that have a body, as used by Elasticsearch
GET-BODY: ^https://search\.example\.com/_search
# WebSockets: matched against the https:// or http:// form of the URL
WEBSOCKET: ^https://stream\.example\.com/events$
```

Patterns are .NET regular expressions, not PCRE.  Rules starting like the above are indexed
by host name, so that the cost of matching does not grow with the length of the whitelist.
The log says how many rules could not be indexed: these get run against every request.
Write `\.` and not `.` in host names so that rules can be indexed.

## Requests that are always refused

Whitelisting a URL means trusting its server to be well-behaved, but not to be free of
loopholes.  As defense in depth, these are refused no matter what the rules say:

  - Headers and query parameters that override the method, such as
    `X-HTTP-Method-Override` and `_method`, or the URL, such as `X-Original-URL`.
  - Headers that claim to be from a proxy trusted by the server, such as
    `X-Forwarded-For`, `X-Forwarded-Host`, and `Forwarded`.
  - Paths that have `..` segments once decoded, such as `/a%2F..%2Fb` or `/a/..;/b`.
    Encoded slashes by themselves are fine: they are normal for npm and GitLab.
  - Protocol upgrades to anything other than WebSockets.

Request bodies are not inspected, so this does not catch `_method` in a submitted form.

## Credentials

Charon can add secrets to requests, so that agents can use APIs without being able to read
any secret.  They are listed in `~/.config/charon/credentials.json`, which is reloaded
when it changes:

```jsonc
[
  // A token in a file.  Replaces any Authorization header from the client.
  {
    "name": "anthropic",
    "origin": "https://api.anthropic.com",
    "url": "^https://api\\.anthropic\\.com/v1/messages",
    "header": "x-api-key",
    "scheme": "",
    "tokenFile": "/home/me/.secrets/anthropic-key"
  },
  // Short-lived tokens from a GitHub App, for the REST API.
  {
    "name": "github-ci",
    "origin": "https://api.github.com",
    "url": "^https://api\\.github\\.com/repos/me/project/actions/",
    "gitHubApp": {
      "appId": "123456",
      "installationId": 7890123,
      "privateKeyFile": "/home/me/.secrets/charon-app.pem",
      "permissions": { "actions": "write" },   // Optional: narrower than the App's.
      "repositories": [ "project" ]            // Optional
    }
  },
  // The same for git over HTTPS, which uses Basic authentication.
  {
    "name": "github-git",
    "origin": "https://github.com",
    "url": "^https://github\\.com/me/project(\\.git)?/",
    "basicUser": "x-access-token",
    "gitHubApp": { "appId": "123456", "installationId": 7890123, "privateKeyFile": "/home/me/.secrets/charon-app.pem" }
  }
]
```

  - The first entry that matches is used.  `url` is a regular expression, but only applies at
    exactly the `origin`, which must be `https`.  So a loose pattern cannot send a secret elsewhere.
  - Credentials grant no access: requests must still be allowed by the whitelist.
  - If a token cannot be obtained, the request fails with status 502 and is not forwarded.
  - The credentials file, token files and private keys are ignored if other users can
    access them.  **They must also be kept out of the sandbox.**
  - Tools in the sandbox can be given any dummy token where they insist on having one.

An agent can do anything with a credential that the rules allow, so make them narrow.
In particular, a URL covered by a credential must not echo request headers back, or the
agent gets to read the secret.

## Differences from mitmproxy-whitelist

  - URLs are built from where the request actually goes, not the `Host` header.
    A `Host` header that disagrees with the destination gets the request refused.
  - Tunnels only carry HTTP in TLS.  Anything else, such as SSH over `CONNECT`, is dropped.
  - `GET` rules do not grant bodies or WebSockets, and some requests are always refused, as above.

## Testing

```
dotnet test
```
