# Automating GitHub from a sandbox, through Charon

This note records how an AI agent in a sandbox was given real, narrowly-scoped
access to GitHub, without any GitHub credential being visible inside the sandbox.
It was first done on 2026-11-05, using this repository as the testbed.

The arrangement:

```
 sandbox                       outside the sandbox
┌────────────────────┐        ┌──────────────────────────────┐
│ git, curl          │        │ Charon                       │        ┌────────┐
│ no credentials     │───────►│  1. checks the whitelist     │───────►│ GitHub │
│ HTTPS_PROXY is set │        │  2. adds the App's token     │        └────────┘
└────────────────────┘        └──────────────────────────────┘
                                 private key of the GitHub App
```

A GitHub App suits this better than a personal access token.  It has an identity of its
own, its permissions are per-repository, and the tokens it issues last an hour.  Charon holds
the App's private key and gets the tokens.  The agent never sees either of them.

## Setting up the GitHub App

1. **Create the App.**  On GitHub: Settings → Developer settings → GitHub Apps → New GitHub App.
   - Give it a name, which must be unique across GitHub, and a homepage URL.
     The URL is required but is not used for anything here.
   - Under Webhook, untick Active.  Nothing needs to receive events.
   - Under "Where can this GitHub App be installed?", choose "Only on this account".
2. **Set the repository permissions.**  These are the ones relevant to CI work:

   | Permission | Access | Needed for |
   |---|---|---|
   | Contents | Read and write | `git push` |
   | Workflows | Read and write | Pushing changes to `.github/workflows/` |
   | Actions | Read and write | Triggering workflows, and reading runs and logs |
   | Metadata | Read-only | Mandatory for all Apps |

   Leave Administration off.  If permissions change after the App is
   installed, the update has to be approved on the installation's page.
3. **Note the App ID**, shown on the App's General page.  It is the `appId` in Charon's configuration.
4. **Generate a private key**, in the same page under "Private keys".  It downloads as a `.pem` file.
   Move it somewhere outside of any sandbox and run `chmod 600` on it, or else Charon refuses to use it.
5. **Install the App.**  Choose Install App in the sidebar, then Install next to your account,
   and "Only select repositories".  Pick just the repositories the agent is to work on.
6. **Find the installation ID**, which identifies this installation of the App.
   It is the number at the end of the URL of the installation's configuration page:
   Settings → Applications → Installed GitHub Apps → Configure.

   ```
   https://github.com/settings/installations/12345678
   ```

An App installed on one repository is what produced the most convincing check of all this:
pushing worked to this repository, and was denied for other repositories of the same account.

## Configuring Charon

`README.md` has the full reference.  What follows is what GitHub needs.

Top-level settings go in `appsettings.json`, in the directory given by `--contentRoot`.  Paths
must be absolute: `~` is not expanded, and a whitelist path that does not exist denies
everything without any error being logged.  Misspelt settings are silently ignored as well.

```
out/publish/Charon/release_linux-x64/charon --contentRoot ~/.config/charon
```

That is the executable compiled ahead of time, by `dotnet publish src/Charon -c Release`.

Credentials go in `~/.config/charon/credentials.json`, which also needs `chmod 600`.
There must be two entries.  The REST API and git are at different origins, and git
uses Basic authentication where the API uses Bearer tokens:

```jsonc
[
  {
    "name": "charon-api",
    "origin": "https://api.github.com",
    "url": "^https://api\\.github\\.com/repos/SteveKCheng/Charon/",
    "gitHubApp": {
      "appId": "123456",
      "installationId": 12345678,
      "privateKeyFile": "/home/steve/.secrets/charon-app.pem",
      "repositories": [ "Charon" ]
    }
  },
  {
    "name": "charon-git",
    "origin": "https://github.com",
    "url": "^https://github\\.com/SteveKCheng/Charon(\\.git)?/",
    "basicUser": "x-access-token",
    "gitHubApp": {
      "appId": "123456",
      "installationId": 12345678,
      "privateKeyFile": "/home/steve/.secrets/charon-app.pem",
      "repositories": [ "Charon" ]
    }
  }
]
```

`appId` is a string and `installationId` is a number.  The IDs above are placeholders.
The optional `repositories` and `permissions` make tokens narrower than the installation.
They can be narrowed further for each agent, in `~/.config/charon/users.json`.

In the sandbox:

  - Set `http_proxy` and `HTTPS_PROXY`, and have clients trust Charon's CA.
  - The git remote must use HTTPS.  SSH remotes cannot work: SSH does not go through
    the proxy, and Charon drops anything but HTTP in TLS from `CONNECT` tunnels.
  - No token or credential helper is needed.  Charon adds the header to the first request,
    so GitHub never responds with the 401 that makes git ask for a password.
  - Plain `curl` works against the API, with no `Authorization` header.  `gh` was not tried.

## URLs to whitelist

Credentials grant no access by themselves: every URL must pass the whitelist as well.
These rules cover what was done in the next section, apart from looking up the versions of
GitHub's own actions with `git ls-remote`, which needs a `GET` rule for `info/refs` of
those public repositories.  They are a reconstruction from the URLs that were used,
and not a copy of the live whitelist:

```
# git: clone, fetch and push
GET: ^https://github\.com/SteveKCheng/Charon(\.git)?/info/refs\?service=git-(upload|receive)-pack$
POST: ^https://github\.com/SteveKCheng/Charon(\.git)?/git-(upload|receive)-pack$

# REST API: reading everything about the repository, including workflows and runs
GET: ^https://api\.github\.com/repos/SteveKCheng/Charon(/|$)

# REST API: triggering a workflow
POST: ^https://api\.github\.com/repos/SteveKCheng/Charon/actions/workflows/[^/]+/dispatches$

# Logs of workflow runs, which are not on github.com: see below
GET: ^https://productionresults[a-z0-9]+\.blob\.core\.windows\.net/
```

The endpoints that were actually called are:

| Method | Path under `https://api.github.com/repos/SteveKCheng/Charon` | Purpose |
|---|---|---|
| GET | (the repository itself) | Find the default branch |
| GET | `/actions/workflows` | See whether a workflow is registered |
| POST | `/actions/workflows/{file}/dispatches` | Start a run manually |
| GET | `/actions/runs?event=...&per_page=5` | Find the run |
| GET | `/actions/runs/{id}/jobs` | Status of the jobs and their steps |
| GET | `/actions/jobs/{id}/logs` | Redirects to the log itself |
| GET | `/check-runs/{id}/annotations` | Warnings and notices from the run |

The logs need a rule of their own.  `/actions/jobs/{id}/logs` answers with a redirect to Azure
blob storage.  Two runs were served from two different hosts, `productionresultssa7` and
`productionresultssa10`, so the rule cannot name just one.  No credential applies there,
and none should: the URL carries its own short-lived signature.  Such URLs will
appear in Charon's Web UI, which is one more reason that it stays out of the sandbox's reach.

The `actions/permissions` endpoint responds with 403, "Resource not accessible by
integration", because it needs the Administration permission.  That is as intended.

## What was done on 2026-11-05

The test was to have the agent set up CI for Charon, working only from inside the
sandbox.  You had already pushed by hand, so `master` and `prototype` were at `bbd25a6`.

1. Checked access through the proxy with `curl`, with no token.  The repository
   could be read, and it had no workflows.
2. Wrote `.github/workflows/build-and-test.yml`, modelled on Mallard's workflow, with
   `workflow_dispatch` as the only trigger.  It restores, builds in Release, and runs the tests.
   Its own token is limited to `contents: read`.
3. Pushed to `master` as `0e63487`.  This could not have been done on a side branch: GitHub only
   accepts dispatches for workflows that are on the default branch.
4. Triggered the run through the API.  The first attempt got a 404, because a new workflow
   takes a few seconds to be registered.  It returned 204 on the retry.
5. [The run](https://github.com/SteveKCheng/Charon/actions/runs/42028904742) succeeded.  Its
   annotations warned that `actions/checkout@v4` and `actions/setup-dotnet@v4` target
   Node.js 20, which is deprecated.
6. Moved to `actions/checkout@v7` and `actions/setup-dotnet@v6`, found with `git ls-remote`, and
   added the `push` trigger for `master`, keeping the manual one.  These were separate commits,
   pushed together.  The push itself then started
   [a run](https://github.com/SteveKCheng/Charon/actions/runs/42029112651) of `b5ea4e8`,
   which succeeded with no more warning about Node.js.
7. Tried to read the job logs, to confirm that the tests had really run.  Charon refused the
   redirect to blob storage, since it was not on the whitelist.  Until that was added, the only
   evidence was indirect: the duration of the step, and the same commands passing locally.
8. Once the rule was added, read the logs of both runs.  Each one has 0 warnings and 0
   errors from the build, and 152 tests passed with none failed.

So this exercised, for real: `git push` with an injected token, including changes to workflow
files, the REST API with an injected token, getting tokens from GitHub, which until then
had only been tried on a stand-in server, and the whitelist stopping something it should.

The whitelist denying the logs turned out to be a useful illustration.  The agent
reported the denial instead of looking for a way around it, and access followed a
decision by a person.  Without logs, an agent can see that a step failed but not why,
so they are worth allowing for any agent working on CI.

## What this does not protect against

  - **Which branch gets pushed to.**  The branch name is in the body of the `POST`, which Charon
    does not read.  The rules above allow pushes to any branch, including force pushes.
    Protecting `master` from an agent takes a ruleset on GitHub, enforced at the server.
  - **Anything that the rules do allow.**  The agent can do whatever the permissions and
    whitelist permit, with your authority.  Whitelisting limits the damage rather than preventing it.
  - **Code that runs in CI.**  A workflow pushed by the agent runs on GitHub's machines, beyond
    the sandbox and the proxy.  Its `permissions` are whatever the pushed file says, up to the
    repository's limits.  So do not give this repository secrets that an agent's
    workflow should not be able to read.
  - **`POST /graphql`.**  One URL can do nearly anything that the token permits, so URL rules
    cannot restrict it.  It should stay off the whitelist for any agent that has a credential.
  - **Separation between sandboxes, beyond credentials.**  Charon can tell its clients apart,
    by a password or by the Unix domain socket they connect to, and give each one tokens for
    only some repositories: see "Proxy users" in `README.md`.  But the whitelist is the same
    for all of them, and clients that do not identify themselves get the credentials as
    they are in `credentials.json`, unless `RequireProxyAuthentication` is set.  To keep
    an agent from even reading something that another may, run another instance.
  - **Endpoints that echo headers.**  A URL covered by a credential that reflects request
    headers would show the token to the agent.
