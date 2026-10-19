# Security policy

## Reporting a vulnerability

Please report security issues **privately**, not in a public issue. Use GitHub's
[private vulnerability reporting](https://github.com/Maytrella007/Hermes-VPN/security/advisories/new)
on this repository. Include what you did, what you expected, and what happened;
a proof of concept helps but is not required.

Expect an acknowledgement within a few days. Once a fix is ready it ships in a
tagged release and the advisory is published with credit, unless you prefer to
stay anonymous.

## Supported versions

This is pre-1.0 software. Fixes land on `main` and the latest release; there is
no back-porting to older tags.

## Scope worth knowing before you look

- **The privileged helper is the one piece that runs as root.** `contrib/vpn-exit`
  is installed mode 750 and granted a passwordless, *exact-path* sudoers rule. It
  is the entire privileged surface, it is short, and it is meant to be read before
  it is trusted. A way to make it run a command it was not meant to, or to accept
  an argument that is not a place name, is the highest-value finding here.
- **The scanner does not read it.** The scripts in `contrib/` have no file
  extension, so Hermes' plugin scanner skips them. A clean scan is not a statement
  about them. That is called out in the README on purpose.
- **This is not an anonymity tool.** Tor mode gives a Tor exit and a clean
  session, not Tor Browser's anonymity set. Fingerprinting defeats it, and
  [docs/DESIGN.md](docs/DESIGN.md) says so. Reports that a determined operator in
  the `docker` group can reach the credentials file are already documented, not
  vulnerabilities: the fix is not putting that user in the `docker` group.

## What counts as a real finding

- The browser leaving by the host's own address when an exit is believed up.
- WebRTC, DNS, or any path out of a sealed sandbox that is not the tunnel.
- The guard letting the browser reach a private or internal address while Tor
  mode's `allow_private_urls` is on.
- Anything that makes the helper act outside its exact-path grant.
