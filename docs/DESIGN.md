# hermes-vpn — design and reference

> **This is the complete reference and the reasoning behind every choice.** The
> short, task-oriented front door is **[README.md](../README.md)**; start there.

Let a [Hermes Agent](https://github.com/NousResearch/hermes-agent) choose which
way its browser leaves — and know which way it actually got.

> It is called *vpn* because that is what people look for, but nothing here
> requires one: an exit is any local proxy, so an SSH tunnel to your own machine
> or a commercial proxy works exactly the same way.

> **you:** browse from Mexico and open my site
> **agent:** *(calls `net_use`)* Now leaving by mx (Mexico): seen as
> 201.x.x.x (Mexico City), checked in 0.9s. Closed 1 browser process, so the
> next page loads through it.

## What it does, and what it deliberately does not

An **exit** is a local proxy. That is the whole abstraction, and it is why this
works with anything: a [gluetun](https://github.com/qdm12/gluetun) container
(50-odd VPN providers, or any WireGuard config), an SSH tunnel, a commercial
proxy. gluetun containers are discovered automatically — they publish their
proxy and carry their own country — and anything else goes in a small file.

**No tunnel is implemented here, and no dependency is added.** gluetun already
solved the hard part: the tunnel, DNS, the kill switch. What was missing is an
agent that can pick an exit and, more importantly, one that *knows where it is*.

| Tool | What it does |
|---|---|
| `net_exits` | the exits available, and which one is in use |
| `net_use` | switch to one — checked first, then applied, then verified |
| `net_where` | where the browser appears to be *right now*, by asking |
| `net_places` | which countries and cities a provider offers — **any** provider gluetun knows |
| `net_harden` | install the browser-wide WebRTC policy, so the protection cannot be lost |
| `net_providers` | which VPNs this host has credentials for, and which have setup guides |
| `net_provider_setup` | what a given provider needs and where to find it, from a shipped guide |
| `net_open` | bring up an exit in a place that has none yet, and switch to it |
| `net_close` | shut one down again |
| `net_lock` | the kill switch: browse by an exit, or not at all |
| `net_failover` | off by default: name a standby exit and let a dead one be swapped for it |
| `net_doctor` | what is protecting this browsing and what is not, with the fix for each gap |

## The kill switch

```bash
hermes vpn lock          # arm it
hermes vpn lock --off    # disarm it
```

Or say *"turn on security mode"* and the agent arms it.

Armed, the browser leaves by an exit or it does not leave. Three things change:

- **Browser tools are refused when the exit stops answering.** The plugin
  checks before each browser call (cached for twenty seconds, so clicking stays
  fast) and holds the call with a plain explanation. Chromium pointed at a dead
  proxy would fail anyway — but it fails *looking like a broken website*, after
  the agent already decided where to go.
- **Switching to `direct` is refused** until the switch is disarmed on purpose.
- **A restart cannot quietly undo it.** If the saved exit is gone, the browser
  is pointed at a dead end instead of being left unproxied: no exit means no
  browsing, not browsing from the server.

### In a sandbox, the seal follows the switch

A profile whose browser runs in a container sits on an **internal** docker
network: no route off this host, whatever the browser is configured with.
That is the strongest guarantee here, because it does not depend on this
plugin being right — and it used to mean that disarming the kill switch
changed nothing in there. There was no "directly" to leave by, while the
sentence said there was.

Now the seal follows the switch:

- **Armed**: internal only, and a browser call is held when the exit cannot
  be confirmed.
- **Disarmed**: the sandbox is also attached to a bridge, which is what makes
  going direct possible at all. It does **not** move the browser: disarming
  while a healthy tunnel is selected leaves you on it. `hermes vpn use direct`
  is the step that takes the exit out of the policy — the same two steps the
  host has always had.
- **Armed again**: the exit goes back into the policy and the bridge is taken
  away.

Going direct applies to the **browser**. `vpn-migrate` also writes
`proxy = http://vpn-exit:8888` into the sandbox's `~/.curlrc`, so curl, pip
and anything else in that shell keep using the tunnel whatever the browser is
doing. Worth knowing before concluding the two disagree — and worth knowing
when reading a measurement, which is why the one below is taken with
`--noproxy`.

While it is off the tunnel, `net_where` says so instead of reporting a
location it could not confirm: the verifier measures *through the relay*, and
there is nothing behind the relay in that state, so the question is put from
inside the container directly. Still a measurement — reporting this host's
address as the sandbox's without asking would be the assumption the rest of
this page refuses to make.

**The cost, stated rather than buried.** While disarmed, what keeps that
browser inside the tunnel is this plugin's state and not docker's refusal,
and a gateway that dies while disarmed leaves the sandbox attached. `doctor`
reports which of the two it is on and why, and says plainly when a sandbox is
open with the switch armed, which is the case that is never meant to happen.

### What the kill switch does not cover

**WebRTC would leak the host's real address, and did here until it was fixed.**
A proxy carries TCP; WebRTC's UDP walks straight past it. Measured through a
working Mexican exit: the test page reported the server's own IPv4 *and* IPv6
while the same page's HTTP request came from Mexico, and the STUN packets were
caught leaving the interface directly.

Whenever an exit is selected, Chromium is now told
`--webrtc-ip-handling-policy=disable_non_proxied_udp`, and it then gathers no
ICE candidates at all.

**The spelling matters.** `--force-webrtc-ip-handling-policy` is the version
quoted all over the internet, and Chrome 145 does not have it. Chromium ignores
unknown switches in silence, so that flag looks applied and does nothing — this
project shipped it for one commit and measured no change, which is how the
difference was found. If you are hardening another browser, verify the switch
exists in *your* build rather than trusting a blog post.

[`webrtc-leak-test.py`](../webrtc-leak-test.py) is the test that found it: it runs
its own STUN server, drives Chrome over the DevTools protocol, waits for ICE to
finish and compares what the browser offers against the host's real addresses.
It exits 0 when clean and 1 on a leak, so it can be run as a check rather than
believed.

**The sandbox is covered differently.** A sandboxed profile (`lab`, `web`) runs
its own Chromium inside a container, and Hermes sets that browser's arguments
itself, so a flag from here never reaches it. There the protection is a managed
Chrome policy *inside* the container, which carries the proxy as well as the
WebRTC setting, on a network with no route off this host. `doctor` reads that
file where the browser reads it, and a country switch writes it back when it is
missing or wrong. See [`after-install.md`](after-install.md).

If the plugin itself fails to load, nothing of this runs either, and the browser
falls back to whatever the gateway's environment says. For a floor that survives
even that, set the dead end in `~/.hermes/.env`:

```
AGENT_BROWSER_ARGS=--no-sandbox,--disable-dev-shm-usage,--proxy-server=http://127.0.0.1:1
```

Then the worst case is a browser that cannot reach anything, rather than one
quietly using the server's own address.

## Failover: a standby you chose, off by default

```bash
hermes vpn failover --standby exit-airvpn-madrid    # name it and arm it
hermes vpn failover --off                           # disarm; the standby is remembered
```

Armed, a browser call that finds its exit dead moves to **the exit you
named** and says so in the same answer you were waiting for. It does not look
for one: a dropped tunnel is the worst moment to be inferring where someone
wanted to be, and the person can decide it once, in advance, and mean it.

Arming it without a standby does not arm anything. It answers with what is
missing — the other providers that have credentials here — so the exchange
goes:

> — Turn on failover.
> — You are on `exit-miami` (surfshark). You also have **airvpn** configured.
> Which city or country should the standby come out of?
> — Madrid.
> — `exit-airvpn-madrid` is the standby, answering at 185.x.x.x in Madrid.
> It is in Spain and you are in the United States: anything that depends on
> where you appear changes when it takes over.

Four things it will not do:

- **Guess.** No standby named, no failover. The refusal says so.
- **Take a standby that is not running.** It is checked the moment it is
  named, and `doctor` checks it again every time it runs, because a standby
  nobody has looked at is exactly what everything is counting on. Bringing a
  tunnel up takes tens of seconds and a browser call cannot wait for that, so
  the standby stays up.
- **Carry on when the standby is down too.** The call is refused and the kill
  switch holds the browser, rather than letting it out by this host's own
  address.
- **Use Tor.** Naming the Tor exit as a standby is refused, and the reason is
  the same one that makes Tor a mode: failover does not enter it, so it would
  put the browser on Tor carrying the cookies of the ordinary session, which
  is the linkage Tor mode exists to break. `net_tor_connect` is how to use
  Tor, deliberately — and selecting that exit with `net_use` has the same
  problem, so it says so when you do.

Three more things that are true of it. It **rides on the kill switch's
check**, which is the only thing that notices a dead exit before a browser
call, so with the kill switch disarmed failover never fires — and both
`hermes vpn failover` and `doctor` say so rather than leaving it to be
discovered. It **waits a minute between moves**, or a flapping tunnel walks
the browser back and forth once per call. And it is **never quiet**: every
swap is announced in the answer the agent was waiting for, written to the
state file, and reported by `doctor`.

A standby is chosen in front of one exit and outlives it, so every switch to
another exit repeats which one it is. A different provider is worth
preferring: when a whole place stops answering, the usual reason is the
subscription behind it, and `net_providers` shows which VPNs this host has
credentials for — adding one is the person's to do, with
`hermes vpn provider <name>` printing what it needs and where, and the
credentials never passing through the agent.

## Two rules it follows

**Verify, never assume.** An exit is only reported as working after a request
through it comes back, and the place reported is the one the far end actually
saw — not the exit's label. If a label and reality disagree, the answer says so.

**Fail closed.** If the exit does not answer, the switch is abandoned and the
browser keeps whatever it had. A switch that silently leaves the browser on the
server's own address is the failure worth designing against: a tunnel believed
to be up is worse than no tunnel, because decisions get made on the belief.

## Why it closes the browser

Chromium takes its proxy as a launch argument, so a change only applies to a
new process. Hermes launches the browser on demand and lets it idle out, so
usually there is nothing to close — but if a session has one open, `net_use`
closes it (politely, then firmly) and the next page load comes up on the new
exit. The agent's own desktop and session stay up; only the browser blinks.

Pass `restart_browser: false` to leave an open browser alone.

## Install

Two halves, and the second one is not optional: the plugin asks, a root-owned
helper on the host acts. Nothing here can install that second half for you,
which is the entire point of it.

```bash
# 1. the plugin, into the profile you will use it from
hermes plugins install Maytrella007/Hermes-VPN --enable

# 2. the host side: the helper, the relays, the sealed networks
contrib/install            # as root: prints the plan, changes nothing
contrib/install --apply    # as root: then does it

# 3. what is protecting this agent's browsing, and what is not
hermes vpn doctor
```

Step 1 needs the repo to be reachable from the host. From a clone you already
have, `hermes plugins install file:///path/to/the/clone --enable` installs the
same thing.

Step 2 prints all six of its steps before touching anything, and it does
**not** write your VPN credentials: it creates the file for them, root-only,
and leaves it to you. [Exits on demand](#exits-on-demand) says what each step
installs, and why none of those scripts has a file extension.

Then `doctor` is the onboarding: every problem it reports comes with the
command that fixes it. Usually that is `hermes vpn harden` (the browser-wide
WebRTC policy) and `hermes vpn lock` (the kill switch) — two commands, not a
manual.

**A Hermes profile is its own `HERMES_HOME`, with its own `plugins/`
directory**, so step 1 installs into one profile and no other. If your agents
are bots with a Bot Screen, keep reading: that is where the three commands
above stop being enough.

## One checkout, every profile

`hermes -p <profile> plugins enable hermes-vpn` answers *"No plugin named
hermes-vpn"* and points back at `hermes plugins install`, which installs a
second copy into that profile. Link one checkout into each profile instead:

```bash
git clone <this repo> ~/src/hermes-vpn          # the one copy

ln -s ~/src/hermes-vpn ~/.hermes/plugins/hermes-vpn
ln -s ~/src/hermes-vpn ~/.hermes/profiles/lab/plugins/hermes-vpn
hermes -p lab plugins enable hermes-vpn
```

One copy to update, one copy to read before trusting it as root, and every
profile on the same version. `doctor` run inside a profile answers for that
profile.

A bot that browses from a container needs two more commands, both covered in
[`after-install.md`](after-install.md): `vpn-migrate`, which moves the sandbox
that is running right now without recreating it, and `vpn-profile-network`, so
the next sandbox Hermes builds is born on the sealed network. Install one
without the other and the arrangement survives until the next `docker rm`.

## Knowing where you could go

The agent should not have to guess whether a provider has Miami. gluetun carries
every provider's server list inside the container, so one running exit can
answer for all of them:

```bash
hermes vpn places                      # the provider in use: 100 countries, 142 cities
hermes vpn places miami                # Cities: Miami (United States)
hermes vpn places --provider mullvad   # what Mullvad would offer, without having it
```

The list is cached, so it still answers when nothing is running. And when a
place is rejected, the failure carries the near names the provider does have
rather than a flat no.

## "Connect to my AirVPN"

Say that and the agent should not have to search the web, or guess. Setup guides
for the 23 providers gluetun supports, plus `custom`, which is a mode rather
than a provider, ship with the plugin (from the gluetun
wiki, MIT — see [providers/NOTICE.md](../providers/NOTICE.md)):

```bash
hermes vpn providers          # what is configured here, and what has a guide
hermes vpn provider airvpn    # the values AirVPN needs and where they come from
```

So the agent can answer "I do not have AirVPN credentials here yet — you need a
private key and an address from AirVPN's config generator; put them in
`/root/vpn-exits/airvpn.env` and I can open exits with it", which is a useful
answer rather than a shrug.

### More than one VPN at a time

One credentials file per provider in the helper's directory — `.env` is the
default, `mullvad.env` is used by `--provider mullvad`. Exits opened for a named
provider carry it in their name, so two subscriptions can both have a Japan
exit. The agent sees the provider *names* through the helper and never the
credentials.

## Exits on demand

`net_use` picks among exits that are already running. To let the agent create
one for a place that has none — *"connect to a server in Miami"* — install the
helper from [`contrib/vpn-exit`](../contrib/vpn-exit):

```bash
contrib/install            # as root: prints the plan, changes nothing
contrib/install --apply    # as root: then does it
```

That installs the helper and this sudoers rule, the relay, the verifier, and a
sealed network plus relay for each profile that browses from a container. It
leaves your credentials to you.

`contrib/install` has no file extension, like the five other scripts in that
directory. One consequence is worth stating rather than leaving to be
discovered: Hermes' plugin scanner reads only files whose extension is on its
list, so it reads none of them — including `contrib/vpn-exit`, the root-owned
helper. A clean scan result for this plugin is therefore not a statement about
those files. Read them yourself before running one as root; they are short, and
they are the entire privileged surface.

By hand, the helper is installed mode 750 as root, and granted a passwordless,
exact-path sudoers rule in its own drop-in file with mode 440 — which is what
`contrib/install` writes, after validating it:

```bash
install -m 750 -o root -g root contrib/vpn-exit /usr/local/sbin/vpn-exit
```

Keep your provider credentials in `/root/vpn-exits/.env`, readable by root
only. The agent can then ask for a country or city without ever being handed
the key that gets it there, and the helper refuses anything that is not a place
name and will only remove containers it created itself.

**Be honest about what that buys.** If the agent's user is in the `docker`
group — the usual setup — it is already root-equivalent on that host and could
read the file through a container. The separation keeps credentials out of
everyday reach and out of accidents; it is not a wall against a determined
agent. The wall, if you want one, is not putting that user in the `docker`
group.

Opening an exit takes tens of seconds, because a tunnel has to be established.
Switching between exits that are already up takes about one.

## Setting up exits

### gluetun (found automatically)

One container per country, each publishing its proxy **on loopback**:

```yaml
services:
  mx:
    image: qmcgaw/gluetun:latest
    cap_add: [NET_ADMIN]
    devices: ["/dev/net/tun:/dev/net/tun"]
    environment:
      VPN_SERVICE_PROVIDER: mullvad      # or any of gluetun's providers
      VPN_TYPE: wireguard
      WIREGUARD_PRIVATE_KEY: ${WG_KEY}
      SERVER_COUNTRIES: Mexico           # becomes the exit's country
      HTTPPROXY: "on"
      HTTPPROXY_LISTENING_ADDRESS: ":8888"
    ports: ["127.0.0.1:8891:8888"]       # loopback only
    restart: unless-stopped
```

A proxy published on `0.0.0.0` is ignored on purpose: that is an open relay, not
an exit.

### Any other container

Publish an HTTP proxy on loopback and give the container the
`managed-by=vpn-exit` label, and it is discovered like a gluetun one — that is
the same label the helper already uses to decide whether a container may be
pointed at a sandbox, rather than a second rule to learn. Two optional labels,
`exit-provider` and `exit-country`, fill in what `list` shows.

They are labels, so they describe and decide nothing. The country failover
matches on is read from a tunnel's own environment, which means a labelled
exit never stands in for another and never gets a stand-in. A container
without the label is never an exit, however many ports it publishes.

### Anything else

`~/.hermes/net-exits.json`:

```json
{
  "exits": [
    {"name": "home", "proxy": "http://127.0.0.1:8118", "country": "Uruguay"},
    {"name": "office", "proxy": "http://127.0.0.1:3128"}
  ]
}
```

**A SOCKS exit works too**, including an SSH tunnel's `-D` port: write
`socks5://127.0.0.1:1080` and it is checked like any other. The check is an
HTTP request *through* the proxy and urllib cannot send one at a SOCKS server,
so curl does the asking, and curl is told `socks5h` so the name is resolved at
the far end rather than here. That matters twice: a locally resolved name
leaks the DNS query past the tunnel, and `.onion` does not resolve at all
without it.

On a host with no curl there is no way to ask, and an exit that cannot be
confirmed is refused rather than assumed. Install curl, or put an HTTP proxy
in front of the tunnel (privoxy, tinyproxy) and point the exit at that.

### Tor

An exit that needs no subscription and no credentials, which is a first here.
[`contrib/tor-exit/`](../contrib/tor-exit) builds one small Alpine image, from
Alpine's own signed packages rather than someone else's container, and runs it
as two services: `exit-tor` is Tor, and `exit-tor-http` is privoxy giving it an
HTTP face so that everything else in this plugin keeps working unchanged.

```bash
docker compose -f contrib/tor-exit/compose.yml up -d    # needs the hermes-exits network
```

Then it is an exit like any other, discovered without a line of configuration:
it wears the `managed-by=vpn-exit` label, which is already how the helper
decides whether a container may be pointed at a sandbox. It shows up in
`hermes vpn list` on `http://127.0.0.1:8899`. The two share
one network namespace, so Tor's SOCKS port stays on **loopback** and nothing
else on the exits network can reach the tunnel directly: the HTTP front is the
only way in. Privoxy is told `forward-socks5t`, so the hostname is resolved by
Tor, which is what makes **`.onion` addresses work** through this exit.

Three things worth knowing before using it:

- **A site that refuses this node can be handed another one.**

  ```bash
  hermes vpn circuit        # or net_new_circuit, on the exit in use
  ```

  It signals Tor's control port from inside the container — the cookie never
  leaves it — and then measures, because a signal that was accepted is not the
  same as a circuit that changed. Tor coalesces these within about ten
  seconds, so asking twice in a row honestly gives one new circuit, and the
  answer says so instead of claiming a move. It is refused on an exit that is
  not Tor, where `net_use` is the right tool.

  Two readings can also differ with nobody asking: Tor builds a separate
  circuit per destination and rotates them on its own. What the tool
  guarantees is that the signal was accepted and that the address it names was
  measured after it.

  In a profile whose browser is in a sandbox, that browser is closed too, and
  the address is measured **from inside the sandbox** rather than through
  this process's own way out — both end at the same Tor daemon and only one
  of them is the browser's path. A new circuit that leaves the old session
  running is not a new circuit, which is why Tor Browser's own "new identity"
  closes your tabs.
**Tor is a mode, not only an exit.** Connecting to it changes the browser as
well as the way out, because a Tor exit carrying the cookie jar of the
ordinary session is theatre: a site that recognises the session knows who it
is talking to whatever address the request arrived from.

Entering it, and leaving it, the browser is closed and **its cookies and
sessions are set aside** — on the way out too, so nothing an onion left
behind is still there when the agent goes back to work. **Logins are lost,
on purpose**, which is why the tool tells the agent to say so first.

Set aside, not deleted: the profile is renamed, so the browser starts with
nothing and whoever wanted that session can still get it back. It stays
inside the sandbox and goes when the container does. A recursive delete run
as root is worth a human reading before it runs, and this plugin's own
scanner agrees — it refuses a package that carries one. While the
mode is on, **JavaScript is off** (what Tor Browser's safest level does, and
the same reasons: it is the surface that fingerprints, that reaches into the
local network and that runs whatever a page feels like running), device
permissions are denied, and the password manager and autofill are off. Pass
`--javascript` when a site needs it, and expect to be told.

It can also be turned on, and off again, **without leaving the mode**. Once in
Tor mode, `hermes vpn tor --javascript` (or `net_tor_connect` with
`javascript: true`) flips it in place: the browser is closed so the next page
reads the new setting, but the session is **kept**, not set aside, which is the
difference from re-entering. `hermes vpn tor --no-javascript` puts it back.
This is for the site that answers an empty-handed 406 without it, so you get
past it on the circuit you are already on rather than starting over. Default is
off; a bare `tor` with no JavaScript flag leaves whatever is set alone.

In a sandbox that is a second managed-policy file, written on the way in and
removed on the way out. On the host it is a profile directory of its own and
`--blink-settings=scriptEnabled=false`, so the ordinary profile is not
destroyed, only unused.

One thing the mode loosens: Hermes refuses to navigate to a hostname that
does not resolve here, which is every onion address, so the mode turns that
refusal off in the profile's config and **this plugin takes over what it can**.
It is an allow-list: it reads the host the way Chrome will dial it — turning
`\` into `/`, taking what follows the last `@`, percent-decoding and folding
under NFKC — and passes only a public IP or a plain DNS name that is not this
machine. An address in a shape the standard parser rejects but the browser
reads (`127.1`, `0x7f000001`), a host that will not parse, and the names that
mean this machine are all refused with the reason. It runs whenever that
config line is present, not only when the state says the mode is on, so a
path that leaves the line behind does not take both guards down at once. Two
things it cannot do: it does not resolve hostnames, so a *name* that points
at a private address (`localtest.me`) is beyond it, and it only sees calls
that pass through this plugin's middleware. It lasts as long as the mode
does: `hermes vpn use <other exit>` ends it by moving somewhere, `hermes vpn
tor --off` ends it and returns to the exit that was in use before Tor, and
`doctor` says so if a setting is ever left behind.

**Connecting is asked for first, and confirmed before anything opens.**

```bash
hermes vpn tor                     # switch to Tor, check it is bootstrapped
hermes vpn tor https://…onion/     # and establish the circuit to that service
```

`net_tor_connect` is the tool behind it, and the order it imposes is the
point. It switches to the Tor exit, reads Tor's own bootstrap state from the
control port, and then fetches the address **from here, not from the
browser**, with a timeout a rendezvous can actually use. Only when something
has come back does it say so, with how long it took.

Until then, a browser call to that onion is **held**, whether or not the kill
switch is armed, because this is not a question about where the browser leaves
from: it is a request that was going to fail. The refusal names the tool to
call. A browser pointed at an onion while going through a VPN exit is held
too, with the real reason — the name cannot resolve there at all.

So the exchange reads the way it should: *connect to Tor* → "this can take a
minute, I will say when it is up" → *the circuit is up, it answered in 9s* →
and then the page opens, on a circuit that already exists.

- **Hermes' own browser tool blocks a `.onion` before this plugin sees it.**
  Found by running a bot through the whole flow: the circuit came up, the exit
  was confirmed as Tor, and `browser_navigate` answered *"Blocked: URL targets
  a private or internal address"*. The reason is upstream of us and is
  reasonable in general: the browser tool resolves the hostname with
  `getaddrinfo` before navigating, as SSRF protection, and an onion address
  does not resolve locally by design — Tor resolves it. An unresolvable name
  reads as private.

  The switch that governs that check is `browser.allow_private_urls` in the
  profile's `config.yaml`, off by default. Turning it on lets the onion
  through and also stops the browser tool refusing loopback and LAN addresses
  in that profile, keeping only the cloud-metadata floor. That is a real
  trade, so Tor mode makes it only for as long as the mode lasts: the line
  goes in under a marker comment when the mode starts, comes out when it
  ends, and the guard in this plugin refuses internal addresses in the
  meantime. The config is copied to a timestamped `.bak-` beside it first,
  with the original's permissions.

  An `allow_private_urls` with no marker above it is somebody's own setting.
  Nothing here removes one: `doctor` reports that the browser is reachable
  from its own host and says to take the line out by hand.
- **Some sites want JavaScript and say so rudely.** Measured through this
  exit, same browser, same circuit: `example.com` and
  `check.torproject.org` load with JavaScript off, and DuckDuckGo's onion
  answers **HTTP 406** until it is on — the browser shows its own error page,
  which reads like the site is down. `--javascript` (or `javascript: true`)
  is the way through, and since it can be flipped in place without leaving the
  mode (above), getting past a 406 does not cost the circuit or the session.
  It is worth saying out loud when it is used, because it hands back the
  surface the mode turned off; `--no-javascript` takes it away again.
- **A cold onion is slow, and the browser has to be allowed to wait.** Measured
  through this exit with the same Chromium the sandboxes run: the same page
  took 5s once Tor had a circuit to that service and over 56s when it did not,
  and a headless Chrome left on its default 30s page-load timeout reported
  `ERR_TIMED_OUT` while the rendezvous was still being set up. Give the first
  load of an onion a minute or two; the ones after it are ordinary. An onion
  that is genuinely gone fails in about a second instead, the same way in
  curl and in the browser, so slow and dead do not look alike.
- **The country changes with the circuit.** Two calls to `net_where` can report
  two different addresses in two different places. That is Tor working, not a
  fault. Cloudflare's trace reports the country as `T1`, which is its code for
  a Tor exit.
- **Failover leaves it alone, in both directions.** A Tor exit declares no
  country, so it is never chosen as a stand-in for a dead exit and never gets
  one itself. Standing in for Mexico with an exit whose country is whatever the
  next circuit picks would be exactly the silent move the rest of this page
  promises not to make.
- **This is not Tor Browser.** It gives the browser a Tor *exit* and a clean
  session, not Tor Browser's anonymity set: this Chromium has its own
  fingerprint, window size and fonts, and a site that profiles those can tell
  one visitor from another whatever the exit node is. Clearing cookies breaks
  the link between sessions; it does not make two visits look like different
  people. Against an adversary who correlates fingerprints,
  this does not help. The exit node also sees anything not carried over TLS,
  and plenty of sites answer Tor with a captcha or a 403.

## Not to be confused with `hermes egress`

Hermes already ships an `egress` command for iron-proxy, its optional
TLS-intercepting egress firewall for sandboxes. That is a different concern —
swapping proxy tokens for real credentials on the way out — and the name is
taken, which is why this plugin's command is `hermes vpn`. If you run
iron-proxy as well, note that both want to set a proxy for outbound traffic;
they have not been tested together.

## Notes worth reading

- **The browser moves, the gateway does not.** Hermes reads the browser's
  arguments fresh at every launch, so the exit can change at runtime. The
  agent's *own* traffic (model calls, searches) is set when the gateway starts.
- **It writes `AGENT_BROWSER_ARGS` into the running process's environment.** A
  plugin should not mutate the environment lightly; it is done here because that
  variable is the documented way Hermes passes arguments to the browser, it is
  read at each launch, and there is no other way to change the exit without a
  gateway restart.
- **The choice survives a restart**, and is re-applied *without* checking it
  first. Two reasons: Hermes gives a plugin ten seconds to import and register,
  and a lookup through a sulky exit can take longer than that — a plugin that
  misses the deadline is dropped, tools and command included. And the
  unverified choice is the safer one: pointing at a dead proxy fails loudly,
  while skipping it sends the browser out by the host's own address with nobody
  the wiser. Checking happens when a tool is used.
- **Labels can lie.** `SERVER_COUNTRIES: Mexico` is what you asked gluetun for,
  not proof. Only `net_where` is evidence.

## Honest about intent

This exists so an agent on a server can browse from somewhere you control, and
so it can tell you when a site is refusing it because it is coming from a
datacenter — which explains a surprising share of unexplained blocks and
verification prompts.

It is also, plainly, a convenient way to change an apparent country, which is
what evading a geographic block looks like. Use it for sites you are entitled to
reach.

## License

MIT. See [LICENSE](../LICENSE).
