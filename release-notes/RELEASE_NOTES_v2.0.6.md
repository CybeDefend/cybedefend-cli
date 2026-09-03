# Release v2.0.6

Version v2.0.6 — September 3, 2026

- Built for multiple platforms
- Precompiled binaries included
- Docker image available at: `ghcr.io/CybeDefend/cybedefend-cli:v2.0.6`

A follow-up to v2.0.5, from a real CI failure. Nothing changes on CybeDefend cloud.

---

## Bug Fixes

### A self-hosted instance reported the wrong problem when it could not be reached

v2.0.5 made the client application and the token resource follow `api_url`, discovered from that instance's `/client-apps`. When that request failed, it fell back to a **region's built-in client application** — which is registered with the cloud and unknown to any other deployment.

So an instance whose `/client-apps` was reachable from a workstation but not from a CI runner reported:

```
token exchange failed (HTTP 400): {"code":"oidc.invalid_client",
  "error_description":"invalid client <an id you never configured>"}
```

That fallback could never have worked. Assuming it replaced a reachability problem with an identity error pointing at the wrong thing, and made it look as though the v2.0.5 fix had not worked at all.

Discovery failure is now **fatal** for any `api_url` that is not one of the two regions, and says what happened:

```
cannot discover the client application from https://api.example.internal/client-apps: HTTP 403
That is the CybeDefend instance named by api_url. Check that it is reachable from
where the CLI runs — a CI runner does not necessarily have the same access as a
workstation
```

The regions keep their built-in application, so a momentary failure to reach `/client-apps` on the cloud does not stop a scan. That fallback now follows `api_url` rather than `--region`, so the two can no longer disagree.

---

## Changes

### `--debug` shows the client application and the token resource

```
[DEBUG] Auth source: flag-pat — api=https://… auth=https://… client=… resource=https://…
```

Those two fields were the only ones the line did not print, and they were exactly the ones an authentication failure turns on. `CybeDefend/cybedefend-action` exposes this as `debug: true` from v2.2.1.

### Discovery timeout raised to 5 seconds

It now decides whether the command runs at all, so it is worth waiting a little longer for a slow instance.

---

## Upgrade Notes

Nothing to do beyond upgrading.

If you scan a self-hosted instance from CI and this release starts failing with `cannot discover the client application`, that failure was already happening — v2.0.5 and earlier hid it behind an `invalid_client` error. The message names the host to make reachable from your runner.
