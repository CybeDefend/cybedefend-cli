# Release v2.1.2

Version v2.1.2 — October 30, 2026

- Built for multiple platforms
- Precompiled binaries included
- Docker image available at: `ghcr.io/CybeDefend/cybedefend-cli:v2.1.2`

A security patch for CVE-2026-98432. It is a drop-in replacement: no configuration change, no migration, no re-login.

---

## Security

### `cybedefend login` no longer opens an MPTCP listener (CVE-2026-98432)

CVE-2026-98432 is a use-after-free in the Linux kernel's IPv4 TCP handshake. The kernel CVE team rates it 9.8 and fixed it upstream in 5.10.272, 5.15.223, 6.1.190, 6.6.159, 6.12.113, 6.18.56 and 7.2.10. Its published exploit needs a Multipath TCP (MPTCP) listener on the target.

Since Go 1.24, a Go program opens its listeners as MPTCP by default when the kernel supports it. `cybedefend login` waits for the OAuth callback on port 9877, bound to every interface. On a Linux machine whose kernel is not patched yet, a login therefore exposed an MPTCP listener to the network until the browser came back, five minutes at most.

The CLI is now built with `godebug multipathtcp=0`, as the Go Security Team advises: the callback listener is a plain TCP socket. To check a binary, run `go version -m cybedefend`: it prints `DefaultGODEBUG=multipathtcp=0`.

What this covers, and what it does not:

- **Only Linux was concerned.** Go uses MPTCP on Linux only, so the macOS and Windows builds behave exactly as before.
- **Only `cybedefend login` opened a listener.** Commands authenticated with a personal access token (`scan`, `results`, `report` in CI, the GitHub Action) open none and were never exposed.
- **This does not patch your kernel.** The bug is in the kernel and is not specific to MPTCP; this release takes the CLI off the published exploit's path. Update the kernel of your Linux workstations and CI runners as your distribution ships the fix.

---

## Upgrading

Nothing to change. Replace the binary, or pull `ghcr.io/CybeDefend/cybedefend-cli:v2.1.2`.

Building from source still requires **Go 1.26**.
