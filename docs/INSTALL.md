# Installing hermes-vpn, step by step

This is the full walk-through, from nothing to a browser that leaves by a
country you chose, with the kill switch on. It is written to be read in order
the first time; after that, [`hermes vpn doctor`](#come-back-to-doctor) is the
one command to return to, because it measures the state rather than trusting
this page.

If you would rather be prompted through it, `hermes vpn setup` does these same
steps interactively. This page is what it is doing, and what to do when a step
needs a decision.

---

## The one thing to understand first

The plugin is deliberately in two halves, and that shape is the whole security
argument:

- **The package** — the `net_*` tools and the `hermes vpn` CLI. This is what the
  agent can see and call, and what Hermes' scanner reads and marks `safe`.
- **The privileged helper** — a separate, root-owned program that is the *only*
  thing that reads VPN credentials and brings tunnels up. The agent cannot
  install it and cannot read what it writes.

Because of that split, **a VPN credential never passes through the agent, the
chat, or any message the model reads.** It is also why there is exactly **one
step in the whole install that needs a terminal and root** (step 2). Everything
else can be driven from the chat.

---

## Before you start

- **Linux** host and a running **[Hermes Agent](https://github.com/NousResearch/hermes-agent)**.
- **Python 3.11+** (3.11 / 3.12 / 3.13 are what CI runs). The plugin adds no
  other Python dependencies.
- **root** on the host for step 2 — a root-owned helper is the point.
- **Docker**, if you want container exits (`hermes vpn open`) or a per-profile
  relay. A plain HTTP/SOCKS proxy on loopback needs none.
- A **VPN account** whose WireGuard config you can generate (any of gluetun's
  ~50 providers, or any WireGuard config). You do **not** need this until step 3.

On a phone (Telegram-first, no shell): everywhere this guide says "a terminal",
use the **Terminal tab in the Hermes dashboard**. It works from the phone and is
a channel the model cannot see, which is exactly why the one secret-handling
step belongs there.

---

## Step 1 — Install the plugin

Into the profile you will use it from:

```bash
hermes plugins install Maytrella007/Hermes-VPN --enable
```

From a clone you already have, instead:

```bash
hermes plugins install file:///path/to/the/clone --enable
```

A catalog install lands in `~/.hermes/plugins/hermes-vpn`. After this the agent
has the tools and you have the `hermes vpn` CLI, but no VPN is set up yet.

> The first `hermes` command after this may print a one-time "resolving /
> installing Python dependencies" block. That is Hermes updating its own
> environment after a source change, not this plugin (which adds none). It
> happens once.

---

## Step 2 — Install the host side (the one terminal + root moment)

Let the wizard find the path for you:

```bash
hermes vpn setup
```

On a fresh host it detects that the helper and sudoers rule are missing and
prints the exact command to run as root, with the path already filled in. Run
it **first without `--apply`** so it prints its plan and the literal sudoers
rule and changes nothing — read that, then apply:

```bash
cd ~/.hermes/plugins/hermes-vpn   # or wherever it installed; `hermes vpn setup` prints the path
sudo contrib/install              # prints all six steps and the exact rule; touches nothing
sudo contrib/install --apply      # then does it
```

What `--apply` sets up:

- the root-owned helper (`vpn-exit`, with its `set-credentials` entry point),
- a **passwordless, exact-path** sudoers rule for just that helper — not a blanket rule, one command only;
  see [`contrib/vpn-exit.sudoers`](../contrib/vpn-exit.sudoers) for
  exactly what the one rule grants,
- the per-profile relay and a sealed network for each profile that browses from
  a container,
- a `/root/vpn-exits/.env` **template** — it does *not* write your credentials.
  That file is the one thing the whole arrangement exists to protect, so you
  fill it in through step 3, never by hand and never in chat.

The wizard runs as the unprivileged agent user and will not attempt this itself,
by design: installing a root helper is yours to do and to read first.

---

## Step 3 — Add a VPN provider (the key never touches the chat)

First, generate the WireGuard config in your provider's own dashboard. Not sure
what it needs? Ask the plugin — it ships the guide:

```bash
hermes vpn provider airvpn        # prints exactly what AirVPN needs and where in its panel to get it
```

For AirVPN, for example, that is a private key, a preshared key and an address
from the Config Generator in the Client Area. gluetun knows the provider's
servers natively, so those few values are all you supply — not the endpoint or
the peer key.

Then store it, one of two ways:

**A — at a terminal** (the most direct; the dashboard Terminal tab counts):

```bash
hermes vpn provider airvpn --set
```

Paste the whole WireGuard config, then press **Ctrl-D**. It writes
`/root/vpn-exits/airvpn.env`, readable only by root. The agent never sees the
key. (An IPv6 tunnel address is dropped automatically on a host without IPv6;
the preshared key is kept.)

**B — by vault reference** (the agent can do this one for you): if you already
keep the config in [`pass`/`gopass`](https://www.passwordstore.org/) or in a
file on the host, give the agent only a *reference*, never the secret:

```bash
hermes vpn provider airvpn --from-ref pass:vpn/airvpn
hermes vpn provider airvpn --from-ref file:/home/you/airvpn.conf
```

The plugin resolves the reference host-side and writes the same root-only file
without the contents ever being a tool return or a message.

> If you offer to paste the key into the chat, the agent is built to **decline**
> and point you back here. That is working as intended, not a refusal to help.

Repeat this step for each provider. You can have several configured at once
(AirVPN *and* Surfshark *and* …), which is what makes cross-provider failover in
step 5 possible.

---

## Step 4 — Open a first exit and verify it

From the chat: *"browse from the Netherlands"*. Or at a terminal:

```bash
hermes vpn open netherlands --provider airvpn
```

This brings up the exit, **measures the address the far end actually sees**, and
only then adopts it:

```
Now leaving by exit-airvpn-netherlands: the far end reports 213.152.162.116 in NL ...
```

Nothing claims a location it did not measure. To check at any time:

```bash
hermes vpn where      # where the browser appears now, by asking the far end
hermes vpn use japan   # switch between exits you already have
hermes vpn list        # the exits, and which one is in use
```

If `open` fails, it is almost always the credential (re-check step 3) or the
country name (ask `hermes vpn places --provider airvpn`). The switch fails
*closed*: a bad exit is abandoned and the browser keeps what it had.

---

## Step 5 — Turn on the protections

A fresh install is **not** armed until you do this (a corrupt state file fails
armed, but a clean one that was never locked does not). `hermes vpn setup`
offers each of these with a line on what it does; by hand:

```bash
hermes vpn harden                 # install the browser-wide WebRTC policy, so your real IP can't leak over UDP
hermes vpn lock                   # the kill switch: no working exit means no browsing, never a fall back to the host IP
```

Optionally, a standby on **another provider**, so a dead subscription is
covered, not just a dead server:

```bash
hermes vpn failover --standby exit-mx   # name a standby that is checked when you name it
```

With failover armed and the kill switch on, if the exit in use stops answering a
browser call moves to the standby and says so; if the standby is down too, the
call is refused rather than let out by the host's own address.

---

## Step 6 — If your bot browses from a container (a Bot Screen)

Skip this if your agent's browser runs on the host. But if the profile's
terminal backend is `docker` — a Bot Screen — its browser runs **inside** the
container, and that changes one thing: loopback in there is not this host, so
the exits (which are loopback addresses here) are not reachable from it. Left
alone, the bot cannot see any exit.

First, a fact no error message mentions: **a profile is its own `HERMES_HOME`,
with its own `plugins/` directory.** The plugin installed in one profile does
not exist for the others, and `hermes -p <profile> plugins enable hermes-vpn`
will say there is no such plugin. Link one checkout into each profile's
`plugins/` instead of installing a copy per profile — the three commands are in
**[DESIGN.md](DESIGN.md#one-checkout-every-profile)**.

The answer to the loopback problem is **one relay per profile**, which
`contrib/install` (step 2) already set up:

```
hermes-vpn-lab (internal) ── vpn-relay-lab ── exit-jp
hermes-vpn-web (internal) ── vpn-relay-web ── exit-mx
```

Each bot sits alone on an `--internal` network: no route off this host, no
external DNS, no UDP. Its only way out is its own relay, so a wrong or missing
proxy setting fails **shut** instead of leaking. One relay per profile is what
makes "this bot in Japan and that one in Mexico" possible, and what stops
changing one bot's country from silently moving the others.

A bot that is **already running** moves onto its relay live, without being
recreated — same PIDs, and Xvnc, the dock and any open browser survive:

```bash
vpn-migrate <container> <profile>     # move the container that exists now onto the relay
vpn-profile-network <profile>         # so the next container Hermes creates is born there
```

Both halves are needed: the first moves the container running now, the second
decides what happens after an image change or a `docker rm`. **You do not need
to delete and rebuild your bots** — once the relay exists, migration is live.

Then verify from inside the sandbox, which is the only honest check here:

```bash
hermes vpn doctor     # reports each profile "checked from inside — OK <ip> <country>"
```

Note that *sealed* is not the same as *isolated from this machine*: an
`--internal` network cuts the bot off from the internet except through the
tunnel, but the bot can still reach this host itself (its gateway). That is the
host's firewall policy to set, not the plugin's — spelled out in
**[after-install.md](after-install.md#what-sealed-does-and-does-not-mean)**.

---

## Come back to doctor

```bash
hermes vpn doctor
```

One command, run as a person right after installing: it leads with a verdict,
then a line per check, and every gap it reports names the command that fixes it.
It measures each profile from inside, so it is the honest answer to "is this
actually protecting me?" — trust it over this page.

---

## Daily use, from here on

Once configured, the day-to-day is conversation — *"connect me to Japan"*,
*"what country does a site see?"*, *"switch me to Surfshark"*. You only return to
a terminal to add another provider by path A.

---

## Going further

- **Prove there is no WebRTC leak**, measured rather than assumed — it runs its
  own STUN server, drives the browser, and compares what it offers against this
  machine's real addresses:

  ```bash
  python3 webrtc-leak-test.py       # 0 clean, 1 on a leak, 2 inconclusive
  ```

  Run it as the user the agent runs as; as root it also captures packets, the
  independent half of the measurement.
- **The full host-side reference** — the compose layout, secrets, and the
  details behind step 6 — is **[after-install.md](after-install.md)**.
- **Why the plugin is shaped this way** — the full design and threat model,
  including *One checkout, every profile* — is **[DESIGN.md](DESIGN.md)**.

---

## Quick reference

| Goal | Command |
|---|---|
| Install the plugin | `hermes plugins install Maytrella007/Hermes-VPN --enable` |
| Guided install | `hermes vpn setup` |
| Host side (root), dry run then apply | `sudo contrib/install` / `sudo contrib/install --apply` |
| See what a provider needs | `hermes vpn provider <name>` |
| Add a provider at a terminal | `hermes vpn provider <name> --set` |
| Add a provider by vault reference | `hermes vpn provider <name> --from-ref pass:… \| file:…` |
| Open an exit and verify | `hermes vpn open <country> --provider <name>` |
| Where am I now | `hermes vpn where` |
| Kill switch on / WebRTC policy | `hermes vpn lock` / `hermes vpn harden` |
| Cross-provider standby | `hermes vpn failover --standby <exit>` |
| Bot Screen: move a running bot onto its relay | `vpn-migrate <container> <profile>` + `vpn-profile-network <profile>` |
| Health check | `hermes vpn doctor` |
