# Release v2.0.7

Version v2.0.7 — September 4, 2026

- Built for multiple platforms
- Precompiled binaries included
- Docker image available at: `ghcr.io/CybeDefend/cybedefend-cli:v2.0.7`

A follow-up to v2.0.6 for self-hosted setups behind a VPN or a proxy. Nothing changes on CybeDefend cloud.

---

## Bug Fixes

### A slow answer from your instance could end the run

v2.0.6 made client-application discovery fatal for an `api_url` that is not one of the two regions — correctly, since the cloud's identity can never authenticate against your instance. But it allowed a single attempt with a 5-second timeout, so a slow answer ended the command rather than merely being unlucky:

```
cannot discover the client application from https://api.example.internal/client-apps:
  context deadline exceeded (Client.Timeout exceeded while awaiting headers)
```

Five seconds is not much when the traffic crosses a VPN, an exit node or a proxy. Observed on a real run: the same instance answered one API call in 8 seconds, the scan completed and the policy was evaluated, and only the report export failed — on the network, not on anything the user had configured.

Discovery now allows **15 seconds** and up to **three attempts** with a short backoff.

A refusal is still reported immediately. Retrying a `403` or a `404` only delays a failure you have to act on, so only transport errors and `5xx` are retried.

---

## Upgrade Notes

Nothing to do beyond upgrading. If a self-hosted scan intermittently failed at discovery while the instance was plainly reachable, this is the fix.

`CybeDefend/cybedefend-action` picks it up in v2.2.3.
