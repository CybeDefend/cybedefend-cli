# Release v2.1.1

Version v2.1.1 — September 12, 2026

- Built for multiple platforms
- Precompiled binaries included
- Docker image available at: `ghcr.io/CybeDefend/cybedefend-cli:v2.1.1`

This release fixes three reporting bugs found by testing the v2.1.0 binary against the live API. Each one was silent: the CLI printed a plausible number instead of failing, so nothing in a pipeline would have flagged it. It is a drop-in replacement: no configuration change, no migration, no re-login.

---

## Bug Fixes

### `compliance stats` reported zero violations for a blocked project

The command read the violation statistics from the wrong place in the API response, so every field fell back to its zero value. A project that a policy had actually blocked was reported as having no violations at all, with an empty compliance status.

On a test project the command printed `totalViolations: 0` and `complianceStatus: ""` while the platform reported one blocking violation and a status of `Non-Compliant`.

**If you gate a pipeline on this output, that gate has been passing everything since the command was introduced.** After upgrading, the same project correctly reports:

```json
{
  "totalViolations": 1,
  "blockedCount": 1,
  "warnedCount": 0,
  "applicablePoliciesCount": 1,
  "complianceStatus": "Non-Compliant"
}
```

`compliance history` and `compliance violations` were unaffected and are unchanged.

### `overview project` always reported a risk score of 0

The cyber risk score and level were read from a field the API does not send, so every project scored `0` at an empty level regardless of its real posture. A project scoring 3684 at level `critical` now reports exactly that.

### `overview org` reported a risk score that does not exist

The organization endpoint returns no risk figure at all, but the CLI emitted `riskScore: 0` anyway — indistinguishable from a genuine zero. The risk fields are now omitted when the platform does not compute them, so an absent score can no longer be mistaken for a clean one.

### SARIF reports carried placeholder tool information

The SARIF `tool.driver` block named `https://example.com/docs` as the tool's home and reported its version as `1.0.0`, frozen since well before v2.1.0. Both are provenance that GitHub code scanning surfaces on every uploaded alert. The block now names the CybeDefend CLI repository and the version that actually produced the report.

The version is now defined in one place and read by both `cybedefend version` and the SARIF exporter, so the two can no longer drift apart.

---

## Upgrading

Nothing to change. Replace the binary, or pull `ghcr.io/CybeDefend/cybedefend-cli:v2.1.1`.

If you parse `overview` output, note that `riskScore` and `riskLevel` are now **omitted** when the platform has not computed them, rather than present and zero. Readers that expected the keys to always exist should treat an absent key as "not computed".
