# hermes-vpn

**An agent on a server browses from a datacenter IP, and every site can tell.** hermes-vpn gives a [Hermes Agent](https://github.com/NousResearch/hermes-agent)'s browser a country you control, and never *claims* a location it has not measured: every switch is confirmed by reading back the address the far end actually saw.

[![tests](https://github.com/Maytrella007/Hermes-VPN/actions/workflows/tests.yml/badge.svg)](https://github.com/Maytrella007/Hermes-VPN/actions/workflows/tests.yml)
&nbsp;·&nbsp; Linux &nbsp;·&nbsp; Docker &nbsp;·&nbsp; needs a Hermes Agent &nbsp;·&nbsp; MIT

> **you:** browse from Mexico and open my site
> **agent:** *(switches exit)* Now leaving by `mx` (Mexico): seen as 201.x.x.x in Mexico City, checked in 0.9s.

It adds **no tunnel and no dependency**. An *exit* is just a local proxy, so any VPN, SSH tunnel or commercial proxy works the same way, and [gluetun](https://github.com/qdm12/gluetun) containers (50-odd providers, or any WireGuard config) are discovered automatically. gluetun already solved the tunnel, the DNS and the kill switch; the piece that was missing is an agent that can pick an exit and *knows which one it really got*.

## What your agent gets

| Tool | What it does |
|---|---|
| `net_use` | switch to an exit, checked first, then applied, then verified |
| `net_exits` | the exits available, and which one is in use |
| `net_where` | where the browser appears to be right now, by asking |
| `net_places` | which countries and cities a provider offers, for **any** provider gluetun knows |
| `net_open` / `net_close` | bring up an exit in a place that has none yet, and shut it down again |
| `net_lock` | the kill switch: browse by an exit, or not at all |
| `net_failover` | name a standby exit and let a dead one be swapped for it (off by default) |
| `net_tor_connect` / `net_new_circuit` | enter Tor as a mode, and ask for a fresh circuit |
| `net_providers` / `net_provider_setup` | which VPNs have credentials here, and what each one needs |
| `net_add_provider` | add a provider from a vault reference (`pass:`/`file:`), so the key never passes through the chat |
| `net_harden` | install the browser-wide WebRTC policy so the protection cannot be lost |
| `net_doctor` | what is protecting this browsing and what is not, with the fix for each gap |

**Verified end-to-end on a live server:** a running bot's sandbox migrated onto a VPN exit without a restart, Tor mode entered and left, and the browser returned to its previous country, each step confirmed by reading the address back from *inside* the sandbox.

## Quick start

```bash
hermes plugins install Maytrella007/Hermes-VPN --enable   # the plugin, into this profile
hermes vpn setup                                          # guided: prints the root install command to run, then a provider and a first exit
```

`hermes vpn setup` is the path that needs no directory: on a fresh host it prints the exact `sudo .../contrib/install --apply` to run as root (with the path filled in for you), then helps you add a provider and open a first exit, and turns on the WebRTC policy and arms the kill switch for you. Prefer the commands one at a time? After `hermes plugins install`, the plugin is not in your current directory, so run the host side from where it installed (a catalog install puts it in `~/.hermes/plugins/hermes-vpn`):

```bash
cd ~/.hermes/plugins/hermes-vpn                          # or wherever it installed; `hermes vpn setup` prints the path
sudo contrib/install --apply                             # the host side, as root: helper, relays, sealed networks
hermes vpn provider <name> --set                         # store your VPN's config at a terminal (dashboard Terminal tab, or SSH), never in chat
hermes vpn open <country>                                # bring up an exit there, switch to it, verify by measuring
```

`hermes vpn doctor` is the one command to come back to, and every gap it reports names the command that fixes it. The tool table above is the full surface, but failover, Tor and composing your own container are optional and can wait.

For a detailed, read-in-order walk-through of everything below — the two-part install, adding a provider without the key touching the chat, and the phone-only path — see **[docs/INSTALL.md](docs/INSTALL.md)**.

> The first `hermes` command after install may print a one-time "resolving / installing Python dependencies" block. That is Hermes updating its own environment after a source change, not this plugin (which adds none), and it happens once.

## Requirements

- **Linux** and a **Hermes Agent**.
- **Python 3.11+** (3.11 / 3.12 / 3.13 run in CI). No other Python dependencies.
- **root** for the host side (`contrib/install`), because a root-owned helper is the whole point of keeping VPN credentials away from the agent.
- **Docker** for container exits (`hermes vpn open`) and the per-profile relay. A plain HTTP or SOCKS proxy on loopback (named in `~/.hermes/net-exits.json`) needs none.
- **gluetun** is optional but the easiest way to get exits (50+ providers, or any WireGuard config); it runs as a Docker container.

## Install

**New here? [docs/INSTALL.md](docs/INSTALL.md) is the full step-by-step walk-through** — from nothing to a browser leaving by a country you chose, with the kill switch on, including the phone-only path. What follows is the short form.

**From the catalog** (what the Quick start shows), into the profile you will use it from:

```bash
hermes plugins install Maytrella007/Hermes-VPN --enable
```

**From a clone you already have:**

```bash
hermes plugins install file:///path/to/the/clone --enable
```

**The host side** installs a root-owned helper and a passwordless, exact-path sudoers rule for it — see **[The privileged helper](#the-privileged-helper)** and [`contrib/vpn-exit.sudoers`](contrib/vpn-exit.sudoers) for exactly what that one rule grants. Run with no `--apply` it prints all six steps, the literal rule included, before it touches anything: read it first. It does **not** write your VPN credentials: it creates the root-only file and leaves it to you. Run it from the plugin's own directory (a catalog install puts it in `~/.hermes/plugins/hermes-vpn`), or run `hermes vpn setup`, which prints the command with the path already filled in.

```bash
cd ~/.hermes/plugins/hermes-vpn   # or wherever it installed; `hermes vpn setup` prints the path
sudo contrib/install              # prints the plan, changes nothing
sudo contrib/install --apply      # then does it
```

**Bots that browse from a container** (a Bot Screen) need two more steps, `vpn-migrate` and `vpn-profile-network`, both covered in **[after-install.md](docs/after-install.md)**. Running several profiles from a single checkout (one copy to update, one to read before trusting as root) is set up in **[docs/DESIGN.md](docs/DESIGN.md#one-checkout-every-profile)**.

## How it works

- **An exit is a local proxy.** That is the whole abstraction, and why it works with anything.
- **Verify, never assume.** An exit is reported working only after a request through it returns, and the place reported is the one the far end saw, not the exit's label. If the two disagree, the answer says so.
- **Fail closed.** If the exit does not answer, the switch is abandoned and the browser keeps what it had. A tunnel believed up is worse than no tunnel, because decisions get made on the belief.
- **The browser moves, not the gateway.** Hermes reads the browser's arguments fresh at every launch, so the country changes at runtime without a restart.

## Commands

```bash
# choosing a country
hermes vpn use mx                 # switch to a running exit
hermes vpn list                   # the exits, and which is in use
hermes vpn where                  # where the browser appears now, measured
hermes vpn places --provider mullvad   # what a provider offers, with or without having it

# the kill switch: browse by an exit or not at all
hermes vpn lock                   # arm it
hermes vpn lock --off             # disarm it

# exits on demand (needs the root helper from contrib/install)
hermes vpn open miami             # bring up an exit there and switch to it
hermes vpn close exit-miami       # shut it down
hermes vpn providers              # which VPNs have credentials here
hermes vpn provider airvpn        # what AirVPN needs and where it goes

# Tor, as a mode: cookies set aside, JavaScript off, a fresh session
hermes vpn tor                    # switch to Tor and wait until it is bootstrapped
hermes vpn tor https://…onion/    # and establish the circuit to that service
hermes vpn tor --javascript       # turn JavaScript on in place (a site needs it), keeping the session
hermes vpn tor --no-javascript    # and off again, without leaving the mode
hermes vpn circuit                # a new circuit, when a site refuses this node
hermes vpn tor --off              # leave Tor and return to the exit used before it

# a standby you chose, off by default
hermes vpn failover --standby exit-airvpn-madrid
hermes vpn failover --off

# health
hermes vpn doctor                 # the checklist, with a fix per gap
hermes vpn harden                 # the browser-wide WebRTC policy
```

Each has an `net_*` tool behind it so the agent can do the same from a sentence (*"turn on security mode"* arms the kill switch).

## Setting up exits

A **gluetun** container is found automatically: publish its HTTP proxy **on loopback** (a proxy on `0.0.0.0` is an open relay, not an exit) and it carries its own country.

```yaml
services:
  mx:
    image: qmcgaw/gluetun:latest
    cap_add: [NET_ADMIN]
    devices: ["/dev/net/tun:/dev/net/tun"]
    environment:
      VPN_SERVICE_PROVIDER: mullvad
      VPN_TYPE: wireguard
      WIREGUARD_PRIVATE_KEY: ${WG_KEY}
      SERVER_COUNTRIES: Mexico
      HTTPPROXY: "on"
      HTTPPROXY_LISTENING_ADDRESS: ":8888"
    ports: ["127.0.0.1:8891:8888"]       # loopback only
    restart: unless-stopped
```

An **SSH tunnel, a SOCKS port or any other proxy** goes in `~/.hermes/net-exits.json`. **Tor** builds from Alpine's own signed packages and needs no subscription. Full recipes, including `.onion` support, are in **[DESIGN.md](docs/DESIGN.md#setting-up-exits)**.

## The privileged helper

On-demand exits need root, so `contrib/vpn-exit` is installed mode 750 as root with a passwordless, **exact-path** sudoers rule. The agent asks for a country; it never touches the VPN key, and the helper only removes containers it created itself.

Be honest about what that buys. The scripts in `contrib/` ship **without a file extension**, which means Hermes' plugin scanner does not read them, so a clean scan is **not** a statement about them. **Read them yourself before running one as root.** They are short, and they are the entire privileged surface. And if the agent's user is in the `docker` group it is already root-equivalent on that host: the separation keeps credentials out of everyday reach, it is not a wall against a determined agent.

## Limits, and what the plugin does about each

These are the edges that selecting an exit does not close on its own. None is left as a silent gap — each is named here with what the plugin does about it:

- **WebRTC** is the one leak a proxy cannot catch: a proxy carries only TCP, so WebRTC's UDP would otherwise carry the host's real address straight past it. So whenever an exit is selected the browser is told to disable non-proxied UDP, `hermes vpn harden` makes that a browser-wide policy so it holds even if the browser is relaunched, and [`webrtc-leak-test.py`](webrtc-leak-test.py) measures it rather than trusting it. For a floor that survives even the plugin failing to load, set a dead-end proxy in `AGENT_BROWSER_ARGS`.
- **Labels can lie.** `SERVER_COUNTRIES: Mexico` is what you asked gluetun for, not proof. Only `net_where` is evidence.
- **This is not Tor Browser.** Tor mode gives a Tor exit and a clean session, not Tor Browser's anonymity set. A site that fingerprints the browser can still tell visitors apart.

Each of these, and the reasoning behind every choice above, is covered in full in **[DESIGN.md](docs/DESIGN.md)**.

## Not to be confused with `hermes egress`

Hermes' `egress` command drives iron-proxy, its TLS-intercepting egress firewall. That is a different concern (swapping proxy tokens for real credentials on the way out), which is why this plugin's command is `hermes vpn`. If you run both, note that they have not been tested together.

## License

MIT. See [LICENSE](LICENSE).
