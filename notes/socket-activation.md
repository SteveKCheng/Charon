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


