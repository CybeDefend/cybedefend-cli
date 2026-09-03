// File: cmd/client_resolution.go

package cmd

import (
	"fmt"
	"strings"
	"time"

	"cybedefend-cli/pkg/api"
	"cybedefend-cli/pkg/auth"
	"cybedefend-cli/pkg/logger"
	"cybedefend-cli/pkg/utils"

	"github.com/spf13/viper"
)

// authSource tells which credential the CLI ended up using.
type authSource string

const (
	sourceFlagPAT   authSource = "flag-pat"   // --pat passed on the command line
	sourceStored    authSource = "stored"     // ~/.cybedefend/credentials.json (cybedefend login)
	sourceConfigPAT authSource = "config-pat" // pat: in the config file, or $CYBEDEFEND_PAT
	sourceNone      authSource = "none"       // nothing usable — the first API call will error out
)

// authInputs is the already-read state that drives credential resolution. It is
// gathered by currentAuthInputs() and kept free of globals so the resolution
// itself stays unit-testable.
type authInputs struct {
	PAT             string // viper-resolved PAT: --pat flag > $CYBEDEFEND_PAT > config file
	PATFlagChanged  bool   // --pat was explicitly passed on the command line
	PATInConfigFile bool   // a `pat:` key sits in the config file (deprecated)

	APIURL            string // viper-resolved api_url
	APIURLFlagChanged bool   // --api-url was explicitly passed on the command line
	RegionFlag        string
	RegionFlagChanged bool

	// Endpoints derived from the current config (region, or explicit overrides).
	AuthEndpoint string
	ClientID     string
	APIResource  string

	Creds *auth.Credentials // stored credentials, nil when none
}

// resolvedAuth is everything needed to build an api.Client.
type resolvedAuth struct {
	Source       authSource
	APIURL       string
	AuthEndpoint string
	ClientID     string
	APIResource  string
	PAT          string
	Region       string            // label of the stored credentials, used to persist refreshed tokens
	OAuth        *auth.Credentials // set when the stored credential is an OAuth one
	Warnings     []string
}

// regionEndpointsFunc resolves the endpoints of a region. Injected so tests never
// reach the network (the real implementation calls /client-apps).
type regionEndpointsFunc func(region string) (apiURL, authEndpoint, clientID, apiResource string)

// resolveAuth applies the credential precedence:
//
//  1. an explicit --pat flag
//  2. the credentials written by `cybedefend login`
//  3. the `pat` of the config file / $CYBEDEFEND_PAT
//
// The order of 2 and 3 used to be inverted, so a stale `pat` left in
// config.yaml (or exported as $CYBEDEFEND_PAT) silently shadowed a successful
// login and every command failed with an opaque `invalid_grant`.
func resolveAuth(in authInputs, endpointsFor regionEndpointsFunc) resolvedAuth {
	var warnings []string

	if in.PATInConfigFile {
		warnings = append(warnings, "`pat:` in the config file is deprecated and will be removed in a future release "+
			"(config.yaml is world-readable). Use `cybedefend login --pat <PAT>` instead: credentials are stored in "+
			"~/.cybedefend/credentials.json with 0600 permissions.")
	}

	// 1. Explicit --pat flag wins over everything, on the endpoints of the current config.
	if in.PATFlagChanged && in.PAT != "" {
		return resolvedAuth{
			Source:       sourceFlagPAT,
			APIURL:       in.APIURL,
			AuthEndpoint: in.AuthEndpoint,
			ClientID:     in.ClientID,
			APIResource:  in.APIResource,
			PAT:          in.PAT,
			Warnings:     warnings,
		}
	}

	// 2. Credentials written by `cybedefend login`.
	if creds := in.Creds; usableCredentials(creds) {
		apiURL, authEndpoint, clientID, apiResource, ok := creds.Endpoints()
		if !ok {
			// Legacy credentials.json (region only) — keep resolving through the region.
			apiURL, authEndpoint, clientID, apiResource = endpointsFor(creds.Region)
		}

		if in.PAT != "" {
			warnings = append(warnings, "a PAT is set in the config file or in $CYBEDEFEND_PAT, and credentials from "+
				"`cybedefend login` also exist. The login credentials are used. Remove one of the two to lift the ambiguity.")
		}
		if in.APIURLFlagChanged && in.APIURL != apiURL {
			warnings = append(warnings, fmt.Sprintf("--api-url is ignored: the credentials stored by `cybedefend login` pin the API to %s. "+
				"Run `cybedefend logout` then log in again to target another instance.", apiURL))
		}
		if in.RegionFlagChanged && !strings.EqualFold(in.RegionFlag, creds.Region) {
			warnings = append(warnings, fmt.Sprintf("--region %s is ignored: the credentials stored by `cybedefend login` are for region %s. "+
				"Run `cybedefend logout` then log in again to switch region.", in.RegionFlag, creds.Region))
		}

		res := resolvedAuth{
			Source:       sourceStored,
			APIURL:       apiURL,
			AuthEndpoint: authEndpoint,
			ClientID:     clientID,
			APIResource:  apiResource,
			Region:       creds.Region,
			Warnings:     warnings,
		}
		if creds.Type == auth.AuthTypeOAuth {
			res.OAuth = creds
		} else {
			res.PAT = creds.PAT
		}
		return res
	}

	// 3. `pat` of the config file / $CYBEDEFEND_PAT — kept for backward compatibility.
	if in.PAT != "" {
		return resolvedAuth{
			Source:       sourceConfigPAT,
			APIURL:       in.APIURL,
			AuthEndpoint: in.AuthEndpoint,
			ClientID:     in.ClientID,
			APIResource:  in.APIResource,
			PAT:          in.PAT,
			Warnings:     warnings,
		}
	}

	return resolvedAuth{
		Source:       sourceNone,
		APIURL:       in.APIURL,
		AuthEndpoint: in.AuthEndpoint,
		ClientID:     in.ClientID,
		APIResource:  in.APIResource,
		Warnings:     warnings,
	}
}

// currentAuthInputs snapshots the viper/flag/credentials state of the running command.
func currentAuthInputs() authInputs {
	in := authInputs{
		PAT:               viper.GetString("pat"),
		PATFlagChanged:    persistentFlagChanged("pat"),
		PATInConfigFile:   viper.InConfig("pat"),
		APIURL:            viper.GetString("api_url"),
		APIURLFlagChanged: persistentFlagChanged("api-url"),
		RegionFlag:        viper.GetString("region"),
		RegionFlagChanged: persistentFlagChanged("region"),
	}
	if config != nil {
		in.AuthEndpoint = config.AuthEndpoint
		in.ClientID = config.AuthClientID
		in.APIResource = config.AuthResource
	}
	// A credentials file that cannot be read is reported, not swallowed: the
	// alternative is an opaque authentication failure further down.
	creds, err := auth.LoadCredentials()
	if err != nil {
		logger.Warn("Ignoring stored credentials: %v", err)
	} else {
		in.Creds = creds
	}
	return in
}

// persistentFlagChanged reports whether a global flag was explicitly set on the command line.
func persistentFlagChanged(name string) bool {
	flag := rootCmd.PersistentFlags().Lookup(name)
	return flag != nil && flag.Changed
}

// newClientFromConfig creates an API client from the resolved credentials.
func newClientFromConfig() *api.Client {
	res := resolveAuth(currentAuthInputs(), regionEndpoints)
	for _, w := range res.Warnings {
		logger.Warn("%s", w)
	}
	logger.Debug("Auth source: %s — api=%s auth=%s", res.Source, res.APIURL, res.AuthEndpoint)

	if res.OAuth != nil {
		expiry, _ := time.Parse(time.RFC3339, res.OAuth.TokenExpiry)
		return api.NewClientWithOAuth(res.APIURL, res.AuthEndpoint, res.ClientID, res.APIResource,
			res.OAuth.AccessToken, res.OAuth.RefreshToken, expiry, res.Region)
	}
	return api.NewClient(res.APIURL, res.PAT, res.AuthEndpoint, res.ClientID, res.APIResource)
}

// newClientFromConfigWithPAT creates an API client using an explicit PAT (used by login --pat).
func newClientFromConfigWithPAT(pat string) *api.Client {
	return api.NewClient(viper.GetString("api_url"), pat, config.AuthEndpoint, config.AuthClientID, config.AuthResource)
}

// regionEndpoints returns the API URL, auth endpoint, client ID and token resource
// for a given region string ("eu" or anything else → us). Only used as a fallback for
// credentials.json files written before the endpoints were persisted.
func regionEndpoints(region string) (apiURL, authEndpoint, clientID, apiResource string) {
	if strings.EqualFold(region, "eu") {
		return utils.APIURLEu, utils.AuthEndpointEu, utils.FetchCLIClientID(utils.APIURLEu, utils.AuthClientIDEu), utils.APIURLEu
	}
	return utils.APIURLUs, utils.AuthEndpointUs, utils.FetchCLIClientID(utils.APIURLUs, utils.AuthClientIDUs), utils.APIURLUs
}

// hasUsableCredentials reports whether a command can authenticate at all, without
// building a client. Used by the pre-flight checks of `scan` and `results`.
func hasUsableCredentials() bool {
	return resolveAuth(currentAuthInputs(), regionEndpoints).Source != sourceNone
}

// usableCredentials reports whether stored credentials actually carry a token.
func usableCredentials(creds *auth.Credentials) bool {
	if creds == nil {
		return false
	}
	switch creds.Type {
	case auth.AuthTypePAT:
		return creds.PAT != ""
	case auth.AuthTypeOAuth:
		return creds.AccessToken != ""
	}
	return false
}
