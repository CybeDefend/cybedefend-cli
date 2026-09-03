# Release v2.0.5

Version v2.0.5 — September 3, 2026

- Built for multiple platforms
- Precompiled binaries included
- Docker image available at: `ghcr.io/CybeDefend/cybedefend-cli:v2.0.5`

This release fixes authentication against **self-hosted deployments**. It is a drop-in replacement: nothing changes on CybeDefend cloud, and no configuration change or re-login is required.

---

## Bug Fixes

### A self-hosted instance could not be authenticated against at all

Three values were derived from `--region`, and only the first of them could be overridden:

| value | derived from | overridable |
|:---|:---|:---|
| auth endpoint | region | ✅ `--auth-endpoint` |
| CLI client id | the region's URL | ❌ |
| token resource | the region's URL | ❌ |

So pointing `--api-url` at your own instance produced a token exchange that presented the **cloud's** identity to **your** auth server: a client application it does not know, and a token audience it does not mint tokens for. Every command failed with an opaque `invalid_grant`, identical whether the PAT was valid or not.

`--auth-endpoint` could not work around it: naming the right auth server does not change the client id or the resource sent to it. There was no combination of flags that worked.

The token resource is now the API you are calling, and the client application is discovered from that same API — `/client-apps` already advertises both. Self-hosted authentication needs only the two addresses:

```yaml
# config.yaml
api_url: "https://api.cybedefend.internal"
auth_endpoint: "https://auth.cybedefend.internal"
```

or the equivalent flags. Set them **together**: `api_url` alone leaves the exchange pointed at the region's auth server.

**On CybeDefend cloud, keep using `region`.** It resolves the API and auth addresses for you and keeps resolving them if either ever changes — setting the two by hand there can only get them out of step. Nothing in this release changes cloud behaviour.

---

## Changes

### The identity provider is no longer named in the codebase

Configuration fields, constants and comments carried the vendor name of the identity provider behind authentication. They now read `AuthClientID` and `AuthResource`, with config keys `auth_client_id` and `auth_resource`.

Neither key was ever read from configuration — both values are computed at startup — so this cannot affect an existing `config.yaml`.

---

## Upgrade Notes

Nothing to do beyond upgrading. If you run against a self-hosted instance, set `api_url` and `auth_endpoint` together and remove any other authentication settings: the client application and the token audience are discovered for you.

`CybeDefend/cybedefend-action` exposes this as the `auth_url` input from v2.2.0.
