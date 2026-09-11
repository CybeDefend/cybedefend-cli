// Package version holds the CLI version as a single source of truth.
//
// The version is reported in two places that must never disagree: the
// `cybedefend version` command and the SARIF `tool.driver.version` field that
// downstream consumers (GitHub code scanning) use for provenance. Keeping the
// constant here means a release bump is one edit, not two.
package version

// Version is the CLI version. Bump this on release; nothing else carries it.
const Version = "2.1.0"
