# hermes-vpn is installed

```bash
hermes vpn doctor
```

That one command tells you what is protecting this agent's browsing and what is
not, and every problem it reports comes with the command that fixes it. Come
back to it after each step below — it measures, rather than taking anyone's
word for it, including this page's.

## The short version

```bash
cd ~/.hermes/plugins/hermes-vpn   # a catalog install puts it here; `hermes vpn setup` prints the exact path
sudo contrib/install              # prints the plan, changes nothing
sudo contrib/install --apply      # then does it
```

That installs the root helper and its sudoers rule, the relay, and a sealed
network for each profile that browses from a container. It does **not** write
your VPN credentials: it creates `/root/vpn-exits/.env` with a template, because
that file is the one thing the whole arrangement exists to protect. You fill it in
with `hermes vpn provider <name> --set` (below), which never lets the key reach the
agent or the chat.

Don't know what your VPN needs in there? `hermes vpn provider <name>` prints it,
from a guide shipped with the plugin — no searching. Then store it and open an exit:

```bash
hermes vpn provider <name> --set   # paste the WireGuard config at the terminal, never in chat
                                   # (or --from-ref pass:vpn/<name> / file:/path if you keep it in a vault)
hermes vpn open mexico             # brings up an exit and uses it, verified by measuring
hermes vpn use japan               # or switch between the ones you have
hermes vpn where                   # where it actually came out, checked
hermes vpn lock                    # kill switch: no exit means no browsing
```

`hermes vpn setup` walks these steps interactively if you would rather be prompted.

Or just tell the agent: *"browse from Mexico"*.

## What an exit is

One gluetun container per country, with its HTTP proxy published **on
loopback**. They are discovered automatically — no configuration lists them:

```yaml
# /root/vpn-exits/docker-compose.yml
services:
  mx:
    image: qmcgaw/gluetun:latest
    container_name: exit-mx         # `exit-…`: how the helper recognises its own
    cap_add: [NET_ADMIN]
    devices: ["/dev/net/tun:/dev/net/tun"]
    environment:
      VPN_SERVICE_PROVIDER: surfshark   # 23 providers have guides here
      VPN_TYPE: wireguard
      WIREGUARD_PRIVATE_KEY_SECRETFILE: /run/secrets/wg_key
      WIREGUARD_ADDRESSES_SECRETFILE: /run/secrets/wg_address
      SERVER_COUNTRIES: Mexico
      HTTPPROXY: "on"               # off by default, and nothing works without it
    secrets: [wg_key, wg_address]
    networks: [hermes-exits]        # the network the relays reach the exits on
    ports: ["127.0.0.1:8891:8888"]
    restart: unless-stopped

secrets:
  wg_key:
    file: ./secrets/wg_key          # root-only, mode 600
  wg_address:
    file: ./secrets/wg_address

networks:
  hermes-exits:
    external: true                  # `hermes vpn open` creates it
```

Which variables your provider needs is what `hermes vpn provider <name>`
answers. Those guides are gluetun's own pages, so they tell you about the
tunnel and nothing about `HTTPPROXY` or publishing the port — the two lines
above that this plugin needs in order to see the container at all. If you
follow a guide literally, `hermes vpn doctor` will tell you exactly that
rather than claiming you have no exits.

The key goes in as a **file**, not as `WIREGUARD_PRIVATE_KEY`: an environment
variable is printed by `docker inspect`, which is an ordinary metadata read
available to anyone in the docker group. `hermes vpn open` does this for you.

The published port must be on `127.0.0.1`. A proxy published on every
interface is an open relay, and this plugin ignores it on purpose.

## Bots with a Bot Screen

First, a fact that no error message mentions: a profile *is* its own
`HERMES_HOME`, with its own `plugins/` directory. This plugin is installed in
one profile and does not exist for the others, and
`hermes -p <profile> plugins enable hermes-vpn` will say there is no such
plugin and send you back to `hermes plugins install`. Link one checkout into
each profile's `plugins/` instead of installing a copy per profile; the
**[docs/DESIGN.md](DESIGN.md#one-checkout-every-profile)**'s *One checkout, every profile* section has the three commands.

A profile whose terminal backend is `docker` runs its own browser **inside**
the container. Loopback in there is not this host, so the exits — which are
loopback addresses here — are not reachable from it.

The answer is one relay per profile, and `contrib/install` sets it up:

```
hermes-vpn-lab (internal) ── vpn-relay-lab (as vpn-exit) ── upstream/lab → exit-jp
hermes-vpn-web (internal) ── vpn-relay-web (as vpn-exit) ── upstream/web → exit-mx
```

Each bot alone on an `--internal` network: no route off this host, no external
DNS, no UDP. Its only way out is its own relay, so a wrong or missing proxy
setting fails shut instead of leaking. One relay **per profile** is what makes
"this bot in Japan and that one in Russia" possible — and what stops changing
one bot's country from silently moving the others.

A sandbox that is already running moves onto it live, without being recreated:

```bash
vpn-migrate <container> <profile>     # same PIDs; Xvnc, the dock and any open browser survive
vpn-profile-network <profile>         # so the next container Hermes creates is born there
```

Both halves are needed: the first moves the container that exists now, the
second decides what happens after an image change or a `docker rm`.

**You do not need to delete and rebuild your bots.** Earlier versions of this
page said to, and it was never true once the relay existed.

## WebRTC

A proxy carries TCP. WebRTC's UDP walks straight past it, and a page that asks
gets the machine's real address while the same page's HTTP request looks like it
came from the exit.

On the host, the plugin passes the browser argument that stops this, and
`hermes vpn harden` writes the same setting as a browser-wide policy so it
holds even if something changes how the browser is launched.

In a sandbox the argument is not available — Hermes sets that variable itself
for the browser it runs in a container — so the protection is a managed policy
**inside** the container, which carries the proxy too. `doctor` reads that file
where the browser reads it, and a country switch writes it back if it is
missing or wrong.

Measured, not assumed:

```bash
python3 webrtc-leak-test.py           # 0 clean, 1 on a leak, 2 inconclusive
```

It runs its own STUN server, drives the browser over the DevTools protocol,
waits for ICE to finish, and compares what the browser offers against this
machine's real addresses. Run it as the user the agent runs as; as root it can
also capture packets, which is the independent half of the measurement.

## What "sealed" does and does not mean

It means no path to the internet except the tunnel. It does **not** mean
isolated from this host: a container on an internal network still has that
network's gateway, which is this machine, because `--internal` only drops
forwarded traffic. If this host answers on port 22, it answers to the sandbox
too. `doctor` names the ports it finds and leaves the decision to you — your
firewall is not this plugin's to change.
