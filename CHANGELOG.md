# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project aims
to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **BREAKING: every tool is `vpn_*` instead of `net_*`.** `net_exits` is
  `vpn_exits`, `net_use` is `vpn_use`, and so on for all fourteen. The names
  were never only ours: geobrowse is an MCP browser server grown from this same
  code, it serves `net_exits`, `net_use`, `net_where` and the rest -- one set
  per browser it runs -- and on a host running both, one agent had two of each
  in reach. Worse, both families described what they moved as "the agent's
  browser", which is true of both and tells them apart for neither.

  It was measured rather than imagined: asked in Spanish to browse from Mexico,
  the agent called this family, moved the bot's own sandbox, read Madrid back
  from ipinfo and only noticed on the second look. It could as easily have
  answered Madrid.

  So the tools are renamed, and the descriptions carry the distinction instead
  of leaving an agent to guess. The seven that really move an exit open with
  what they move -- "Moves THIS BOT'S OWN network" -- and all fourteen end by
  naming the other family and what it is for. Both sentences are appended in
  one loop over `TOOLS` rather than typed into fourteen descriptions, so a tool
  added later cannot be registered without them; a test asserts that, and that
  no tool is named `net_*` any more. `vpn_places` and the other tools that only
  answer questions do not claim to move anything, because they do not.

  The CLI is unchanged: it was always `hermes vpn ...`, which is where the new
  prefix comes from.

## [0.3.0] - 2026-10-21

### Changed (plugin-catalog review)
- **No model tool edits Hermes' `config.yaml` any more.** Entering Tor mode used
  to write `browser.allow_private_urls` (which turns off Hermes' own SSRF guard)
  from a path the model could reach. Disabling a core guard is a person's call
  now, so the edit moved to a terminal-only command, **`hermes vpn allow-onion`**
  (and `--off`). It explains the change, asks you to confirm, and then restarts
  Hermes itself so it takes effect (via `NET_EXITS_RESTART_CMD`, a detected
  systemd `--user` unit, or a printed fallback). The Tor flow, the onion guard
  and `net_doctor` all hand you that one command and hold onion navigation until
  you run it.
- **`hermes vpn provider <name> --from-ref` now confirms first.** Before writing
  a root-only credentials file from a vault reference it says what it will do and
  asks, and refuses when there is no terminal to confirm at.
- **Credential entry is terminal-only; the `net_add_provider` model tool is gone.**
  Adding a provider from a vault reference stays on the human CLI (`hermes vpn
  provider <name> --from-ref`); there is no tool the agent can drive to do it. The
  plugin now registers fourteen tools, not fifteen.
- **The browser sandbox is not weakened.** `browser_args` no longer forces
  `--no-sandbox`; it appends only the proxy and WebRTC flags to whatever Hermes set,
  so core keeps the sandbox on when it can.
- **The active profile comes from `ctx.profile_name`,** captured in `register()`,
  instead of importing the private `hermes_cli.profiles` core module.
- **The gluetun image is pinned by digest** (`qmcgaw/gluetun:v3.41.3@sha256:...`),
  not `:latest`, since the root helper pulls and runs it with NET_ADMIN.

## [0.2.0] - 2026-10-19

### Changed
- **`hermes vpn setup` turns on both protections by default instead of asking.**
  The wizard installed the WebRTC policy and armed the kill switch only if you answered
  two yes/no prompts whose safe answer was always yes; it now just does them and says how
  to relax each. The kill switch already defaulted to armed; this makes the WebRTC policy
  match.
- **The README quick start shows the real first-run sequence.** It listed `hermes vpn use
  mx`, which only works once an `mx` exit exists; it now shows `provider <name> --set` then
  `open <country>` (nothing to browsing from another country in four commands), notes that
  failover/Tor/custom compose are optional, and warns that the first `hermes` run may print
  a one-time Hermes dependency-install block that is not this plugin.
- **Provider setup guides lead with the one action, not a wall of wiki text.**
  `hermes vpn provider <name>` now opens with the three steps that actually set it
  up (generate the config in the provider's dashboard, store it with `--set` at a
  terminal or `--from-ref` from a vault, then `open`), and drops the gluetun
  docker/compose TLDR and the server list from what it prints. The TLDR omitted the
  HTTPPROXY/loopback settings this plugin needs, so copying it misled; the dashboard
  field steps are kept. The vault path is framed as what it is (for people who keep
  secrets in `pass`/gopass or a file, and for a hands-off agent-driven add), not as a
  terminal-free path it cannot be.
- **`hermes vpn doctor` leads with a verdict and a legend.** The report now starts
  with "All clear - nothing needs action." or "N thing(s) need action." and a one
  line explaining the marks (`✓` good, `·` note, `✗` needs action), on the CLI
  path as well as the tool path, so a reader can tell "fine" from "act" at a glance.

### Added
- **Add a provider from a vault reference, on the human CLI: `hermes vpn
  provider <name> --from-ref`.** The config lives in a password store and the
  command is told only a *reference* to it, never the key. The plugin resolves
  the reference on the host and writes the root-only credentials file; only a
  confirmation comes back. References are `pass:folder/item` (the `pass`
  password store, or gopass, both local and GPG-backed) and `file:/absolute/path`;
  a raw secret or an `env:` reference is refused, so a key can never be pasted in
  as if it were a reference. Terminal only: there is deliberately no model tool
  for it, so the agent can never drive credential entry.
- **Guided first-run: `hermes vpn setup`.** One terminal command walks the
  whole first run in order — checks the host side is installed, shows `doctor`,
  offers to add a provider (through the terminal `--set` path, so the secret
  never reaches the agent), opens a first exit and verifies it by measuring,
  then offers the WebRTC policy and the kill switch. Replaces having to know the
  sequence of separate commands.
- **The agent now drives provider setup end to end** without ever handling the
  key: when asked to connect to a VPN it reads the guide, hands credential entry
  to `hermes vpn provider <name> --set` in your terminal (the Terminal tab in
  Hermes Desktop or the dashboard, or your shell over SSH), declines a key pasted
  into the chat, then confirms with `net_providers` and opens the exit. Every
  "no provider configured" message now names that one next command.
- **One-command credential entry: `hermes vpn provider <name> --set`.** Run on
  the host, it prompts at the terminal, takes the provider's WireGuard config
  (or gluetun's own variable names), and writes the root-only
  `/root/vpn-exits/<name>.env` for you, so a second provider no longer means
  hand-editing a root file. The agent cannot run it: the helper refuses
  credential entry unless stdin is an interactive terminal, and the agent only
  ever reaches the helper with its output captured. Each provider's setup guide
  now names the exact file and offers this command.
- **Toggle JavaScript inside Tor mode without leaving it.**
  `hermes vpn tor --javascript` / `--no-javascript` (and `net_tor_connect` with
  `javascript`) now flip the setting in place, keeping the session, so a site
  that needs scripting (DuckDuckGo's onion answers an empty 406 without it) can
  be reached on the circuit you are already on. Default stays off.
- `pyproject.toml`, and `SECURITY.md` / `CONTRIBUTING.md` / this changelog.
- Long-form docs moved under `docs/` (`DESIGN.md`, `after-install.md`); the
  README is now the task-oriented front door.

### Security
- **Hardened the vault-reference resolver after a final adversarial audit.** Three
  independent review passes found no critical or high issue — the invariant that a VPN
  credential never reaches the model, the chat or the logs held on every path. The
  low-severity hardening: a `pass:` reference may no longer begin with `-` (it could
  otherwise be read as an option by `pass`/`gopass`), a `file:` reference may no longer
  contain `..`, and the password-store error detail is built from stderr only, so a
  decrypted entry written to stdout can never be folded into an error that flows back.

## [0.1.0] - 2026-10-18

First working release. Everything verified end-to-end on a live server.

### Added
- **Named exits for the agent's browser.** An exit is any local proxy; gluetun
  containers are discovered automatically. `net_use` switches, checks, and then
  verifies against the address the far end actually saw.
- **The kill switch** (`net_lock`): browse by an exit or not at all, and it
  survives a restart rather than quietly falling back to the host's address.
- **Sealed sandbox.** Container-browsing profiles sit on an `internal` docker
  network with no route off the host; the seal follows the kill switch.
- **WebRTC leak closed**, measured by `webrtc-leak-test.py` rather than assumed.
- **Exits on demand** through a root-owned, exact-path helper, so the agent names
  a country without ever handling the VPN credentials.
- **Opt-in failover** (`net_failover`): a standby exit you choose in advance,
  same country, announced in the answer the agent was waiting for.
- **Tor as a mode** (`net_tor_connect`, `net_new_circuit`): cookies set aside,
  JavaScript off, a fresh circuit on demand, `.onion` support, and the previous
  exit restored on the way out.
- **`net_doctor`**, provider setup guides for 23 providers, and `net_places`.
- CI on Python 3.11 / 3.12 / 3.13.
