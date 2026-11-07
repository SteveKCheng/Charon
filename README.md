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

## Proxy users

Agents can be given narrower credentials than the defaults, by being users of the proxy.  They
are listed in `~/.config/charon/users.json`, which is reloaded when it changes, and is ignored
if other users of the computer can access it.  Keep it out of sandboxes.

```jsonc
[
  {
    "name": "agent-charon",
    "password": "some long random text",   // Or "passwordSha256": "…" in hexadecimal
    "credentials": {
      "charon-api": { "repositories": [ "Charon" ], "permissions": { "actions": "write" } },
      "charon-git": { "repositories": [ "Charon" ] }
    }
  }
]
```

An agent identifies itself through the URL of the proxy, in the variables `http_proxy` and
`HTTPS_PROXY`, as `http://agent-charon:password@localhost:8080/`.

  - Users are an added layer of safety to opt into.  A user's list says how credentials differ for
    it, by their name in `credentials.json`.  **Credentials not listed apply as they do for
    anyone.**  To keep a user from a credential, give it an empty scope, as described below.
    A misspelt name therefore does not narrow anything, though it gets a warning in the log.
  - Credentials are still applied only to the URLs given in `credentials.json`.  So those
    URLs, and the whitelist, have to cover all the repositories of all the users.
  - Clients that do not identify themselves get the credentials as they are in `credentials.json`,
    unless `RequireProxyAuthentication` is set to true, which has them refused.
  - A wrong user name or password is always refused.  It does not count as not identifying oneself.
  - This limits the damage from agents making mistakes.  It does not protect agents from each other:
    an agent knows its own password, which could end up in its transcript, for example.

**git and .NET programs do not send the password until asked for it**, and without
`RequireProxyAuthentication` they never are.  So they would quietly get the defaults.  For git,
set the environment variable `GIT_HTTP_PROXY_AUTHMETHOD=basic` in the sandbox, or else use
`RequireProxyAuthentication`.  Other programs tested (`curl`, Python, Node.js and Claude Code) send it
regardless.  The column `user` of the traffic database and the Web UI show who a request was from.

### Unix domain sockets

Instead of a password, a user can have a Unix domain socket of its own.  Whoever connects to it
is that user, so there is nothing for an agent to know, and nothing that can leak.  What is
sent in `Proxy-Authorization` there is ignored.  This also avoids the problem with git above.

```jsonc
[
  {
    "name": "agent-charon",
    "socket": "/run/user/1000/charon/agent-charon/proxy.sock",
    "credentials": { "charon-git": { "repositories": [ "Charon" ] } }
  }
]
```

  - A user with a socket needs no password, and without one, it can only use its socket.
    It can have a password too.
  - Paths must be absolute, and at most 107 bytes.  The directory is created if needed, private
    to the owner.  Sockets left behind by a process that died are replaced.
  - Sockets follow the file of users, within a couple of seconds, with no need to restart.
    If a user is removed, connections that it had open get refused.  If the file is
    edited into something invalid, the sockets stay as they are until it is fixed.
  - If a socket cannot be used, because something else is at that path, that is reported in the log,
    and it is tried again every second.  A socket that gets deleted is also recreated.
  - Have the sandbox bind the **directory** of the socket, not the socket itself.  The socket is
    replaced whenever the proxy restarts, and a bind mount stays with the old one.
  - Clients need a forwarder inside the sandbox, as they expect a proxy at a TCP address.  For example:
    `socat TCP-LISTEN:8080,bind=127.0.0.1,fork UNIX-CONNECT:/path/to/proxy.sock`.

### Scopes of tokens

For a GitHub App, `permissions` and `repositories` set what tokens can do, both in `credentials.json`
and for each user.  They only ever narrow what the installation of the App has.  The value
matters, and the difference between these is easy to miss:

| Value | Meaning |
|---|---|
| A list, or an object for `permissions` | Just these |
| `null` | No restriction: all that the installation of the App has |
| Empty: `[]` or `{}` | Nothing: no token is issued, and requests fail with status 502 |
| Left out, for a user | Whatever `credentials.json` says.  Leaving it out there is the same as `null` |

The values for a user replace those in `credentials.json`.  They are not combined.  So a user's
list can have more than the one in `credentials.json`, up to what the installation has.

Credentials that come from a `tokenFile` cannot be narrowed.  Giving a user any of these settings
for one means that it cannot use the credential: requests then fail with status 502.

## Traffic database

All requests are recorded in an SQLite database, which outlasts restarts of the proxy.  It is at
`~/.local/state/charon/traffic.db`, and can be queried at any time with `sqlite3`, even
as the proxy runs.  The view `traffic` has the most useful columns, with readable times.

```sql
-- What is being denied, and why?
SELECT method, url, reason, note, count(*) AS hits
FROM requests WHERE NOT allowed
GROUP BY 1, 2, 3, 4 ORDER BY hits DESC;

-- Which rule let this through?
SELECT time, url, rule FROM traffic WHERE url LIKE '%example.com%';

-- What did the whitelist say when something was denied?
SELECT contents FROM whitelists WHERE hash =
  (SELECT whitelist FROM requests WHERE NOT allowed ORDER BY time_ms DESC LIMIT 1);
```

| `reason` | Meaning |
|---|---|
| `no GET rule`, `no POST rule`, `no PUT rule` | No rule of this type matches the URL |
| `no GET-BODY rule`, `no WEBSOCKET rule` | As above: these need their own type of rule |
| `no rule can allow this` | An HTTP method, or protocol upgrade, that no rule can grant |
| `forbidden request` | Always refused: `note` tells what about it |
| `host mismatch` | The `Host` header is not where the tunnel goes |
| `bad request` | Not a valid request for a proxy |
| `credential unavailable` | The credential named in `note` could not be obtained |
| `CONNECT not first` | `CONNECT` is only understood at the start of a connection |
| `no HTTP in tunnel` | The client never got to make a request: maybe it pins certificates, or is not speaking HTTP |
| `wrong proxy credentials` | The user name or password of the proxy is not right |

A request without a `status` never finished, because the proxy stopped while it was in progress.

Requests are written in the background, within a moment of being made, so the database is
not on the path of requests.  That also means that recording can fail without stopping the
proxy.  Such problems show up in the log and at the top of the Web UI.  What could not be
recorded, if the queue overflows, is counted in the table `gaps`.

These settings control it:

| Setting | Default | |
|---|---|---|
| `TrafficDatabaseFile` | `~/.local/state/charon/traffic.db` | Empty for no database |
| `TrafficRetention` | `14.00:00:00` | Requests older than this are removed |
| `TrafficDatabaseMaxBytes` | 256 MiB | The oldest requests are removed to stay under this |
| `TrafficHeaders` | `false` | Also record headers |
| `TrafficHeadersMaxBytes` | 16 KiB | Limit for each request and each response |

The file does not shrink as requests get removed: the space is reused instead.  The limit does not
count the write-ahead log, which is about 16 MB at most, and can be exceeded by a little
between checks.  There has to be a limit, because clients could otherwise fill the disk.

The database must be accessible to its owner only, like the files of credentials: it is created
that way, and it is not used otherwise.  URLs can contain secrets.  Keep it out of sandboxes.

To keep a copy, do not use `cp` while the proxy is running, as recent writes
are in another file.  This takes a consistent copy:

```
sqlite3 ~/.local/state/charon/traffic.db ".backup /some/where/copy.db"
```

### Headers

With `TrafficHeaders` on, the table `headers` has the headers of requests and responses, as JSON
arrays of pairs of names and values.  This includes requests that were denied.

```sql
SELECT r.url, e.value ->> 1 AS user_agent
FROM requests r JOIN headers h USING (session, id), json_each(h.request) e
WHERE lower(e.value ->> 0) = 'user-agent';
```

What is recorded for requests is as received from the client, so injected credentials are never
in it.  The values of `Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`, `X-Api-Key`,
`Api-Key` and `X-Auth-Token` are replaced with `[redacted]`, and so is any value in a
response containing the secret just injected.  Other headers that happen to contain secrets are not
detected.  Headers over the limit are cut off, and marked with a last pair named `(truncated)`.

Headers take up much more space, so the database then holds far fewer requests within its
limit.  Under very heavy load they are dropped before anything else, which `gaps` keeps count of.

## Differences from mitmproxy-whitelist

  - URLs are built from where the request actually goes, not the `Host` header.
    A `Host` header that disagrees with the destination gets the request refused.
  - Tunnels only carry HTTP in TLS.  Anything else, such as SSH over `CONNECT`, is dropped.
  - `GET` rules do not grant bodies or WebSockets, and some requests are always refused, as above.

## Versions

Versions come from Git history, through [GitVersion](https://gitversion.net/).  Building
needs a Git repository: exported source trees fail, and a shallow clone gets the wrong version.
The Web UI shows the version running, such as `0.0.1-18+fe963fe`, which ends with the commit.
It has `.modified` after that if the working tree had uncommitted changes when it was built.

## Testing

```
dotnet test
```
