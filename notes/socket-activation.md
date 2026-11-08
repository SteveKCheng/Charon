# General discussion on how to implement socket activation compatible with systmed

<a id="turn-20261107"></a>
<turn timestamp="20261107T143503">

## [2026-11-07] How does the option `Accept=no` in systemd work?

<query>

### User's query

Regarding socket activation in systemd, could you explain how the `Accept=no` option works?

I understand `Accept=yes`: systemd accepts incoming connections and passes the newly connected socket to a newly launched process. Very easy to understand.

But `Accept=no` seems a little magical in that both the systemd and the target server progam are both listening? But if it can really allow the server to be started on first use, that would be great. I'm writing/designing a server program that has fairly heavy state — in fact, a HTTP(S) proxy, where the clients cannot be relied on to maintain persistent connections — so it's almost essential to have a multiplexing server. Yet ideally I'm running on my  desktop PC and don't use this filtering proxy all the time, so I want it to auto-start and not take up resources when it is idle. What are the requirements on the server program to make that work robustly?
</query>

<response>

### AI's response: introduction

There is no magic, just a clever handoff of file descriptors.

To clear up the misconception: **systemd and your target server are not both listening at the same time.**

Here is exactly how `Accept=no` works under the hood:

1. **Systemd binds and listens:** When systemd boots, it creates the socket, binds it to the specified port, and calls `listen()`. The proxy service itself is not running yet.
2. **A client connects:** A client attempts to connect to the port. The operating system places this connection into the socket's accept queue.
3. **Systemd wakes up:** Systemd detects the pending connection, but because of `Accept=no`, it **does not** call `accept()` to establish the connection itself.
4. **Systemd launches the proxy:** Systemd spawns your proxy service process and passes the *listening* socket to it (typically as File Descriptor 3) via environment variables.
5. **The proxy takes over:** Your proxy starts up, detects the inherited listening socket, and calls `accept()` on it. It pulls the pending client connection off the queue and begins serving it.
6. **Systemd steps back:** From this point on, your proxy owns the listening socket. All subsequent client connections go directly to your proxy. Systemd stops monitoring the socket entirely until your proxy process terminates.

### Requirements for your Server Program

To make this work robustly for a multiplexing HTTP(S) proxy that saves resources when idle, your code needs to implement three specific things:

**1. Inherit the socket instead of binding it**
Your program must bypass its normal `socket()`, `bind()`, and `listen()` routines. Instead, it needs to check if it was launched by systemd and grab the inherited file descriptor.
* Systemd communicates this using environment variables: `LISTEN_PID` (which should match your process ID) and `LISTEN_FDS` (the number of passed file descriptors).
* The first passed socket is always File Descriptor `3`.
* If you are writing in C/C++, you can use the `sd_listen_fds()` function from `libsystemd`. Most modern languages (Go, Rust, Python) have libraries or built-in support for systemd socket activation that handle this automatically.

**2. Handle multiplexing normally**
Once you have File Descriptor 3, you plug it into your event loop (epoll, kqueue, select, or your language's async runtime) just like you would a socket you created yourself. You call `accept()` on it to handle the initial connection that woke the service up, and it will continue to accept all future connections.

**3. Implement a self-terminating "Idle Timeout"**
This is the most critical requirement for your specific goal of saving desktop resources. **Systemd knows how to start your service on demand, but it does not know when your service is "idle."**

Because it is a multiplexing server (`Accept=no`), systemd assumes the service should run indefinitely once started. To achieve your resource-saving goal:
* Your proxy program must track its own active connections.
* If the active connection count drops to zero, start a timer (e.g., 5 or 10 minutes).
* If a new connection arrives, cancel the timer.
* If the timer expires, have your proxy gracefully close the socket and exit with a success code (`exit(0)`).

When your proxy exits, systemd detects the process termination. It will automatically take back control of the socket and go back to step 1—waiting patiently for the next connection to wake your proxy up again.
</response>
</turn>


# Plan for socket activation in Charon

Written on 2026-11-07, after the discussion above, and after Charon learnt to listen on
lists of addresses (`ProxyListen` and `UiListen`).  All of the steps were done on 2026-11-08,
with the differences noted.  What remains is to try it with the real units.

## What makes Charon unusual

Most servers treat all of their sockets the same, so they can listen on whatever systemd passes.
Charon has three roles of socket: for the proxy, for the Web UI, and for each user of the proxy
who has one.  So it must work out the role of each socket that it is passed.

Socket activation is meant here for a desktop PC, so that Charon takes no memory while no agents
are running.  It is practical with a handful of sockets, not with many: every socket that should
start Charon has to be listed in the `.socket` unit as well as in Charon's own settings.

## Principles

Charon's own settings decide what it listens on, whether or not it was started by systemd:

  - Charon listens on the addresses in its settings, and on the sockets of users in `users.json`,
    exactly as it does now.
  - If systemd passes a socket bound to one of those addresses, Charon uses it instead of
    binding one itself.
  - Addresses that systemd does not pass, Charon binds itself, as now.
  - A socket that systemd passes but that matches nothing gets a warning, and connections
    to it are accepted and closed at once.  Ignoring it would be worse: with `Accept=no`,
    systemd stops watching it once Charon runs, so its clients would hang with no error.

So a mistake in the `.socket` unit can make Charon not start on demand, but it cannot change
what Charon listens on, or in which role.

## Recognizing the sockets

No names are needed: each socket says what it is bound to.  This was tried with
`systemd-socket-activate` on fd 3 to 6, bound to `127.0.0.1:18080`, `[::]:18081`, `[::1]:18082`
and a Unix domain socket.  `new Socket(new SafeSocketHandle(fd, ownsHandle: false))` calls
`getsockname(2)`, and gave:

| fd | `LocalEndPoint` | Also |
|---|---|---|
| 3 | `IPEndPoint 127.0.0.1:18080` | |
| 4 | `IPEndPoint [::]:18081` | `DualMode` is true |
| 5 | `IPEndPoint [::1]:18082` | `DualMode` is false |
| 6 | `UnixDomainSocketEndPoint` with the path | |

`SocketType` gives `Stream`.  There is no property for whether the socket is listening, but
`GetRawSocketOption` reads `SO_ACCEPTCONN` (level 1, option 30 on Linux).  Kestrel's
`ListenHandle(fd)` served a request on the inherited Unix domain socket, and left its file in
place on stopping: .NET removes the file only of a socket that it bound itself.

`LISTEN_FDNAMES` is then needed only for messages in the log.

Matching compares addresses exactly, in the same normalized form that `ListenAddresses` uses
to find duplicates: `IPEndPoint.ToString()`, or the path as written.  Hence:

  - `ListenStream=8080`, without an address, binds `[::]:8080` for IPv4 and IPv6 together.
    That matches only `"[::]:8080"` in the settings, not `"127.0.0.1:8080"`.
    The `.socket` unit should spell out the same addresses as the settings.
  - Paths of Unix domain sockets must be written the same in both places,
    and not reached through symbolic links.

## Steps

### 1. Reading what systemd passes

A new class, `InheritedSockets`, created once at startup:

  - Takes nothing unless `LISTEN_PID` is the process's own ID, like `sd_listen_fds(3)`.
    Then it unsets `LISTEN_PID`, `LISTEN_FDS` and `LISTEN_FDNAMES`.
  - Wraps fd 3 to 3 + `LISTEN_FDS` − 1 in `Socket`s.  Each one that is not a listening stream
    socket gets a warning and is closed.  That covers `Accept=yes`, which passes connected
    sockets, `ListenDatagram=`, and FIFOs.  If `Socket` cannot be made at all for an fd, that
    is not a socket.
  - Keeps the rest by normalized address, with `TryTake(EndPoint)` to claim one.

`FD_CLOEXEC` is not set on these descriptors by systemd, but Charon starts no other
programs, so that is left alone.

The reading of the environment is kept apart from the wrapping of descriptors, so the tests can
give it sockets of their own, without needing them to be on fd 3 onwards.

### 2. The addresses in `ProxyListen` and `UiListen`

In `CharonApp`, each address is first looked up with `TryTake`.  If found, the socket goes to
Kestrel by `ListenHandle`, with the same setup as now for its role.  Otherwise Charon binds it
as now: `UnixSockets.TryPrepare` will find systemd's socket live at a path, and so refuse to
start, only if that socket was not passed, which is the right outcome.

Charon logs, at startup, which addresses came from systemd and which it bound itself.  Sockets
that Charon binds itself go away when it exits, so connecting to them does not start it again.
A `.socket` unit that leaves something out then shows in the journal.

As done, Kestrel is given the `Socket` itself, through a listener of Charon's own, instead
of the number of the descriptor by `ListenHandle`.  Otherwise both Kestrel and
`InheritedSockets` would own the descriptor, and close it.

### 3. The sockets of users

What is left after step 2 goes to `UserSocketListener`, as a pool:

  - When starting a user's socket, the check that runs every second takes it from the pool if it
    is there, instead of binding.
  - When stopping an inherited socket, it goes back to the pool instead of being closed.  Charon
    cannot make systemd stop listening, and the user may be added back.
  - Inherited sockets that no user has, at startup or later, get a warning that names their
    addresses.  They are accepted and closed at once, as above.
  - Inherited sockets are never removed from the file system.  If one's file is deleted anyway,
    the check binds a new socket at the path as now, and the inherited one stays in the pool,
    unreachable.

Adding a user then works as now, but the new socket starts Charon on demand only once it is
added to the `.socket` unit as well.  With a handful of agents, that is manageable.

### 4. Exiting when idle

A new setting, `IdleTimeout`, null by default, for not exiting.  When Charon has had no
connections for that long, it calls `IHostApplicationLifetime.StopApplication()` and exits
with 0.  So the traffic database is written out as on any stop.

  - It takes effect only if Charon was passed at least one socket.  Otherwise nothing would start
    it again, so it is a warning instead.
  - Connections are counted by connection middleware on every listener: the proxy, the
    Web UI, and the sockets of users.  The time starts when the count drops to 0.
  - A connection that arrives while Charon is stopping is not lost if it is to an inherited
    socket: it waits in the socket's queue, which systemd keeps open, and starts Charon again.
  - An agent that is still running but idle does not keep Charon up for long.  Kestrel
    closes idle keep-alive connections after `KeepAliveTimeout`, 130 seconds by default.
    That was checked for HTTP/1.1 inside a tunnel: closed after 132 seconds, and Charon
    exited 5 seconds after that, with `IdleTimeout` at 5 seconds.  HTTP/2 inside tunnels
    has not been checked.

What is lost when Charon exits, and gets re-created when it starts again:

  - The GitHub tokens cached in memory.  They are fetched again, which takes a round trip to
    GitHub on the first request.
  - The recent requests that the Web UI shows, which are kept in memory.  They are still in
    the traffic database.  Loading the latest ones from there at startup could come later.

Whether connections to the Web UI count is a setting, `IdleTimeoutCountsWebUI`, true by
default.  An open tab keeps one connection open, for the stream of requests, and either
choice can be argued: the tab may be open because Charon is still wanted, or forgotten
among dozens of others.

  - **If they count, the default:** an open tab keeps Charon running.  To let it
    exit, close the tab.
  - **If they do not count:** Charon exits with the tab open, and the browser tries to
    reconnect within seconds.  If the UI's socket is inherited, that starts Charon again, and
    the cycle repeats every time the timeout runs out.  So with this choice, the UI's address
    should be left out of the `.socket` unit: the tab then just shows that it is disconnected,
    until Charon is started by something else.

### 5. Documentation

A section in `README.md`, with units like these:

```ini
# ~/.config/systemd/user/charon.socket
[Socket]
ListenStream=127.0.0.1:8080
ListenStream=[::1]:8080
ListenStream=127.0.0.1:8081
ListenStream=%t/charon/agents/claude/proxy.sock
# systemd's default is 0666, which would let any local user use the credentials.
SocketMode=0600
DirectoryMode=0700

[Install]
WantedBy=sockets.target
```

```ini
# ~/.config/systemd/user/charon.service
[Service]
ExecStart=%h/bin/charon --contentRoot %h/.config/charon
# Exiting when idle is with status 0, and must not count as a failure.
Restart=on-failure
```

`%t` is `$XDG_RUNTIME_DIR`, `/run/user/1000`.  The paths in `appsettings.json` and `users.json`
must come out the same as written here.

`Type=notify` is not needed: systemd keeps connections queued while Charon starts, so
`Type=simple` does.

## Testing

  - Unit tests for reading the environment: `LISTEN_PID` that is someone else's, a missing or
    malformed `LISTEN_FDS`, and that the variables get unset.
  - Tests with sockets made by the tests themselves, given to `InheritedSockets` directly:
    - matching for each role;
    - unmatched sockets refusing connections;
    - sockets that are not listening, or not stream sockets;
    - the pool, with a user removed and then added back.
  - That Charon does not remove the file of an inherited socket, on stopping or when a user goes.
  - End to end with `systemd-socket-activate`, which is part of systemd, using the AOT
    executable.  It clears the environment, so `-E` is needed for anything that has to get
    through.  Charon starts on the first connection, and that connection is served.  Charon then
    exits when idle, and starts again on the next connection, with no connection refused.
  - With the real units under `systemctl --user`, which is for you to do: it is outside of
    the sandbox.
