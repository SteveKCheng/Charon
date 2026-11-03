# Firewalling REST APIs

<a id="turn-20261103"></a>
<turn timestamp="20261103T090226">

## [2026-11-03] Avoiding leaks of GitHub credentials

<query>

### User's query

I have a question about authentication to GitHub. Suppose I want to use an AI agent to automate something like setting up a CI workflow. Clearly I should create some kind of restricted access token on GitHub just for that purpose. But if I pass the token to the AI agent as a ‘password’, it can be re-played — which is a security risk since all my interactions go through an upstream LLM service.

With SSH, agent forwarding can be used so that the AI agent does not see the private key material, but I don't think that works for invoking actions on GitHub using its REST API.

I see there is also OAuth authorization available on GitHub. Could that be set up in a way that the AI agent cannot ever discover the credentials, but authentications are routed through some kind of proxy server I run outside of the sandbox that I put my AI agents in?
</query>

<response>

### AI's response

Your analogy to SSH agent forwarding is spot-on. Routing the AI’s requests through a credential-injecting reverse proxy is exactly the right architectural pattern to keep secrets out of the LLM’s context window and protect against token replay attacks.

While you mentioned OAuth, a **GitHub App** is fundamentally better suited for this architecture than an OAuth app. OAuth tokens are tied to a human user account and are often long-lived. A GitHub App acts as its own bot identity, has strictly scoped permissions per repository, and uses a cryptographic private key to generate short-lived (1-hour) Installation Access Tokens.

Here is how you can set up this proxy architecture so the agent never discovers the credentials:

*   **The AI Agent (Inside Sandbox):** You configure the agent’s GitHub integration to point to your local proxy's URL (e.g., `[http://github-proxy.local](http://github-proxy.local)`) instead of `[https://api.github.com](https://api.github.com)`. The agent has no GitHub credentials. To prevent unauthorized local services from using the proxy, the agent can authenticate to it using a simple, locally-scoped dummy token or mutual TLS (mTLS).
*   **The Proxy Server (Outside Sandbox):** You run a lightweight reverse proxy (often built in Go, Node.js, or using a programmable proxy like Envoy) on a secure network boundary. This proxy securely holds the GitHub App’s `.pem` private key and its Installation ID.
*   **Credential Injection:** When the proxy intercepts an API request from the agent, it uses the private key to generate a 1-hour Installation Access Token from GitHub in the background. It then injects this token into the request as an `Authorization: Bearer <TOKEN>` header and forwards it to the real GitHub REST API.
*   **The Resulting Security:** Because the token injection happens entirely outside the sandbox, the token is never passed into the agent's memory. If the upstream LLM service logs the agent's prompts, or if the agent is tricked into exfiltrating its environment variables, the attacker only gets the internal URL and the local dummy token—both of which are completely useless outside your private network.

By putting a proxy in the middle, you also gain the ability to turn it into an **API Firewall** for your agent. Because LLMs can be unpredictable or susceptible to prompt injection, you shouldn't rely solely on GitHub's permissions to constrain them.

With a proxy, you can enforce strict egress filtering before the request ever reaches GitHub:
*   **Endpoint Whitelisting:** If the agent's only job is CI automation, the proxy can drop everything except `POST` requests to the specific `/actions/workflows/{id}/dispatches` endpoint.
*   **Payload Inspection:** You can parse the outgoing JSON body to ensure the agent isn't passing malicious parameters or attempting to run unauthorized workflow branches.
*   **Audit Logging:** You get a verifiable, local log of exactly what the agent attempted to do, independent of the LLM provider's logs.
</response>
</turn>


<a id="turn-20261103-1"></a>
<turn timestamp="20261103T092308">

## [2026-11-03] The dearth of open-source HTTP(S) firewalling tools

<query>

### User's query

Thank you. I already run a HTTP(S) proxy that whitelists URLs the AI agent is allowed to use. I cobbled my solution together using [mitmproxy](https://www.mitmproxy.org/). I had to make my own add-in, so clearly what I'm doing does not seem to be the mainstream purpose of mitmproxy. And mitmproxy, being written in Python, might not have enough performance if I were to really scale up my agentic workflow.

I'm aware there is also Caddy and Envoy, but they seem pretty difficult to set up for what I want to do — compared to mitmproxy, where the MITM part was easy and well-documented. But in this age of AI coding, I'd think lots of people ought to be doing what I'm planning.

Yet there appears to be a dearth of tools. I even had to make my own sandboxing solution, with [Bubblewrap (`bwrap`)](https://github.com/containers/bubblewrap), before I even got started. Is mostly everybody just doing their AI coding ‘un-sandboxed’? It wouldn't be too surprising, given all the hysteria around AI ‘unsafety’ nowadays. Could you survey the landscape of open-source tools for API firewalling (if possible designed for AI agents), to see if there's anything out there before I commit to building my own solution for a “HTTP(S) firewall”?
</query>

<response>

### AI's response: introduction

You are running into a tooling gap caused by a category collision in the AI security market. For the past couple of years, the industry has aggressively built tools for the wrong network boundary, conflating "LLM Firewalls" with "Agent Firewalls".

Most open-source AI security tools fall into two buckets that don't help your architecture:
1. **LLM Firewalls (e.g., NeMo Guardrails, LlamaFirewall):** These sit between the user and the model to screen for prompt injections or jailbreaks. They inspect text, not network actions.
2. **AI Gateways (e.g., LiteLLM, Vercel AI Gateway, Apache APISIX):** These route traffic *to* LLM providers (OpenAI, Anthropic) to handle rate limiting, caching, and API key management.

Because you are trying to govern the agent's *outbound* calls to external systems (like GitHub), you need an **Agent Egress Firewall**. This category has finally started to mature into dedicated open-source and source-available tools that offer the performance of compiled binaries (solving your Python/mitmproxy bottleneck) without the configuration nightmare of Envoy.

Here is the current landscape of purpose-built egress tools for AI agents:

### 1. Pipelock
Pipelock is arguably the closest drop-in replacement for what you are building. It is explicitly designed as an "agent egress firewall" that enforces HTTP and WebSocket inspection.
* **Architecture:** Ships as a single compiled Go binary with zero runtime dependencies. This gives you the high concurrency network performance that mitmproxy lacks.
* **Features:** It sits between the agent and the network to handle URL whitelisting, SSRF (Server-Side Request Forgery) defense, and runtime audits of what the agent actually fetches or sends.

### 2. agentgateway
Built by Solo.io with community contributions, this tool is designed specifically around the "Credential Broker for AI" (CB4A) proxy model.
* **Architecture:** It acts as the Policy Decision Point (PDP) separating the agent from the credentials.
* **Features:** It proxies the agent's egress calls, enforces policy, and injects the sensitive bearer credential into the outbound request just in time. It handles exactly the token exchange flow needed for your GitHub App Installation Access Tokens.

### 3. Clavitor Proxy
Clavitor is a network-layer credential injection proxy that runs locally on your infrastructure.
* **Architecture:** It is built entirely around keeping secrets out of agent sandboxes, memory, and environment variables.
* **Features:** Inside your `bwrap` sandbox, the AI agent uses a dummy placeholder URI (e.g., `clavitor://GitHub/token`). When the HTTP request hits the Clavitor proxy on the way out, it resolves the placeholder locally and injects the real GitHub token into the headers before forwarding it to the API.

### 4. MCP-Specific Gateways
If your agentic workflow relies on the Model Context Protocol (MCP) rather than raw HTTP REST calls, the tooling landscape shifts slightly. Tools like **Docker MCP Gateway** and **Agent Wall** are designed specifically to broker and firewall tool calls between agents and MCP servers. They enforce identity and validate payloads before the tool execution ever happens.

Since you already have the sandbox boundary established with `bwrap`, dropping a single-binary egress firewall like Pipelock or agentgateway outside that namespace will give you the high-performance CI/CD automation you want, without having to write and maintain a custom Python MITM interceptor.
</response>
</turn>


<a id="turn-20261103-2"></a>
<turn timestamp="20261103T094426">

## [2026-11-03] Object-capability security model versus probabilistic ‘virus-scanning’

<query>

### User's query

Thank you, great overview. However, I have to say my philosophy right from the start h:w
as been different though: I base my operational model on ‘capabilities’ (in the sense of security theory): and that means whitelisting what an AI agent is allowed to do. In my `bwrap` sandbox that means I list out each path in my home directory, each URL pattern, each network service, etc. that the AI agent can access. Naturally, my private credentials are out of the whitelist and that's why I was asking how they could be injected on behalf of the AI agent outside of the sandbox.

On the other hand, the approach of scanning for malicious prompt injections, etc. seem to be more of a blacklisting approach. I think the danger is that ‘default allow’ + blacklist is liable to miss loopholes. Am I wrong? It's like ACLs for filesystem permissions which are difficult to get right in practice, whereas at least in my experience, whitelisting gives one more confidence that the sandbox is tight enough.

I don't scan for prompt injections now, because with sandboxing, they can't do damage to my system, and I also don't give access to my external accounts to AI agents. Admittedly, prompt injection in the AI-generated code is possible but at least I *am* reviewing the code that they write.
</query>

<response>

### AI's response

Your architectural philosophy aligns perfectly with fundamental security engineering. You are not wrong; the AI industry’s current fixation on prompt injection detection is essentially an attempt to build a signature-based antivirus for a non-deterministic system, which is a mathematically unwinnable game.

By relying on a "default allow + blacklist" model, LLM firewalls assume they can enumerate all possible bad behaviors or malicious semantic encodings. Because language is infinite and models are probabilistic, attackers will always find a loophole.

Your approach of using `bwrap` for strict isolation and a credential-brokering proxy operates on the **Object-Capability Model** and **Default Deny**. By stripping the agent of ambient authority and explicitly granting it narrowly scoped capabilities (specific paths, specific URLs, injected tokens it cannot read), you secure the infrastructure mathematically rather than probabilistically.

However, while your sandboxing makes the infrastructure bulletproof, you must account for the **Confused Deputy Problem** within the agent's whitelisted boundaries as you scale.

If an agent is strictly constrained to only read GitHub issues and push code to a specific repository, the host OS and your private credentials are safe. But if an external attacker submits a malicious payload in a GitHub issue that the agent reads (an indirect prompt injection), the agent can still be hijacked to abuse its *authorized* capabilities.

In a perfectly sandboxed environment, a successful prompt injection could still cause the agent to:
*   **Weaponize the output:** Write a backdoor into the C++ or Python code it was instructed to generate.
*   **Data exfiltration via authorized channels:** Encode its internal context or the contents of the whitelisted files it has access to, and append them as parameters to the authorized CI webhook `POST` request.
*   **Resource exhaustion:** Trap itself in an infinite loop of executing a whitelisted compiler command or network request, burning compute cycles.

Your current backstop—manually reviewing all AI-generated code before it executes or merges—is the correct mitigation for this. As you build out your unprivileged AI agent framework, the goal is not to scan for prompt injections, but to strictly validate the *outputs* of the agent's actions (e.g., fuzzing the generated code, enforcing strict schemas on outbound JSON payloads) to ensure that even a compromised agent cannot do anything useful for the attacker.

</response>
</turn>


