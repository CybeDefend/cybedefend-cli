// File: cmd/root.go

package cmd

import (
	"fmt"
	"os"
	"strings"

	"cybedefend-cli/pkg/logger"
	"cybedefend-cli/pkg/utils"

	"github.com/mattn/go-colorable"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile           string
	config            *utils.Config
	isUsingConfigFile bool
	isConfigTrusted   bool
	region            string
)

var rootCmd = &cobra.Command{
	Use:   "cybedefend",
	Short: "CybeDefend CLI for interacting with the CybeDefend API",
	Long:  `CybeDefend CLI is a CLI tool to interact with the CybeDefend API.`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Load configuration
		var err error
		config, err = utils.LoadConfig(cfgFile)
		if err != nil {
			return err
		}

		// Display the ASCII art banner if CI is false
		if !config.CI {
			displayBanner()
		}

		if isUsingConfigFile {
			logger.Info("Using config file: %s", viper.ConfigFileUsed())
		}

		// Detect deprecated --api-key / CYBEDEFEND_API_KEY / api_key usage and abort.
		apiKeyFlagChanged := cmd.Root().PersistentFlags().Lookup("api-key").Changed
		_, apiKeyEnvSet := os.LookupEnv("CYBEDEFEND_API_KEY")
		apiKeyInConfig := viper.InConfig("api_key")
		if apiKeyFlagChanged || apiKeyEnvSet || apiKeyInConfig {
			patURL := "https://us.cybedefend.com/profile/personal-access-tokens"
			if strings.ToLower(viper.GetString("region")) == "eu" {
				patURL = "https://eu.cybedefend.com/profile/personal-access-tokens"
			}
			logger.Error("╔══════════════════════════════════════════════════════════════╗")
			logger.Error("║           AUTHENTICATION METHOD DEPRECATED                   ║")
			logger.Error("╚══════════════════════════════════════════════════════════════╝")
			logger.Error("--api-key / CYBEDEFEND_API_KEY / api_key is fully deprecated")
			logger.Error("and no longer accepted by the CybeDefend API (HTTP 410 Gone).")
			logger.Error("")
			logger.Error("Please migrate to a Personal Access Token (PAT):")
			logger.Error("  1. Create a PAT at: %s", patURL)
			logger.Error("  2. Replace --api-key <key>  →  --pat <your-pat>")
			logger.Error("  3. Replace env CYBEDEFEND_API_KEY  →  CYBEDEFEND_PAT")
			logger.Error("  4. Replace api_key: in config  →  pat:")
			os.Exit(1)
		}

		return nil
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		logger.Error(err.Error())
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	// Global flags
	rootCmd.PersistentFlags().String("api-url", utils.APIURLUs, "API URL")
	rootCmd.PersistentFlags().String("pat", "", "Personal Access Token (PAT) — create one in Account Settings → Personal Access Tokens")
	rootCmd.PersistentFlags().String("auth-endpoint", "", "Auth endpoint URL (optional, derived from --region by default)")
	rootCmd.PersistentFlags().Bool("ci", false, "CI mode")
	rootCmd.PersistentFlags().Bool("debug", false, "Debug mode")
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "Config file (default is $HOME/.cybedefend/config.yaml) (optional)")
	rootCmd.PersistentFlags().StringVar(&region, "region", "us", "Platform region to use: us or eu (ignored if --api-url is provided)")

	// Deprecated --api-key flag kept for detection/error messaging only.
	rootCmd.PersistentFlags().String("api-key", "", "[DEPRECATED] Use --pat instead")
	rootCmd.PersistentFlags().MarkHidden("api-key")

	bindFlagsToViper()

	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(resultsCmd)
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(projectCmd)
	rootCmd.AddCommand(teamCmd)
	rootCmd.AddCommand(overviewCmd)
	rootCmd.AddCommand(reportCmd)
	rootCmd.AddCommand(complianceCmd)
	rootCmd.AddCommand(containerCmd)
	rootCmd.AddCommand(loginCmd)
	rootCmd.AddCommand(logoutCmd)
}

// bindFlagsToViper wires the persistent flags into viper. Extracted so it can be
// re-applied after a viper.Reset() in tests.
func bindFlagsToViper() {
	viper.BindPFlag("api_url", rootCmd.PersistentFlags().Lookup("api-url"))
	viper.BindPFlag("pat", rootCmd.PersistentFlags().Lookup("pat"))
	viper.BindPFlag("auth_endpoint", rootCmd.PersistentFlags().Lookup("auth-endpoint"))
	viper.BindPFlag("api_key", rootCmd.PersistentFlags().Lookup("api-key"))
	viper.BindPFlag("ci", rootCmd.PersistentFlags().Lookup("ci"))
	viper.BindPFlag("debug", rootCmd.PersistentFlags().Lookup("debug"))
	viper.BindPFlag("region", rootCmd.PersistentFlags().Lookup("region"))
}

func initConfig() {
	viper.SetConfigName("config") // Name of config file (without extension)
	viper.SetConfigType("yaml")   // REQUIRED if the config file does not have the extension in the name
	// Kept for project-level settings (project_id, branch, …), but a config file
	// found here is written by whoever wrote the repository being scanned, so it
	// is untrusted: utils.EnforceConfigTrustBoundary strips api_url,
	// auth_endpoint and pat from it below.
	viper.AddConfigPath(".")                 // Look for config in the current directory
	viper.AddConfigPath("$HOME/.cybedefend") // Optionally look for config in the user's home directory
	viper.AddConfigPath("/etc/cybedefend/")  // Optionally look for config in /etc/cybedefend/

	// Must come last: viper.SetConfigName clears any previously set config file,
	// so setting it earlier made --config silently fall back to path discovery.
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	}

	// Read in environment variables that match
	viper.SetEnvPrefix("CYBEDEFEND")
	viper.AutomaticEnv()

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		isUsingConfigFile = true
	}

	// Trust boundary: a config file discovered in the working directory must not
	// be able to redirect the PAT exchange, the API host or supply a token.
	var neutralized []string
	isConfigTrusted, neutralized = utils.EnforceConfigTrustBoundary(viper.GetViper(), cfgFile)
	if len(neutralized) > 0 {
		logger.Warn("Ignoring %s from untrusted config file %s", strings.Join(neutralized, ", "), viper.ConfigFileUsed())
		logger.Warn("These settings are only read from $HOME/.cybedefend/config.yaml, /etc/cybedefend/config.yaml, an explicit --config, a flag or a CYBEDEFEND_* environment variable.")
	}

	// Derive API URL from region unless explicitly overridden by flag, env, or a trusted config file
	// api-url flag has priority over region; env CYBEDEFEND_API_URL and a trusted config api_url also have priority
	apiURLFlag := rootCmd.PersistentFlags().Lookup("api-url")
	_, apiURLEnvSet := os.LookupEnv("CYBEDEFEND_API_URL")
	apiURLInConfig := isConfigTrusted && viper.InConfig("api_url")
	if !(apiURLFlag != nil && apiURLFlag.Changed) && !apiURLEnvSet && !apiURLInConfig {
		r := strings.ToLower(viper.GetString("region"))
		var derived string
		switch r {
		case "eu":
			derived = utils.APIURLEu
		default:
			derived = utils.APIURLUs
		}
		viper.Set("api_url", derived)
	}
}

// displayBanner prints the ASCII art banner
func displayBanner() {
	// White
	color := "\033[97m"
	reset := "\033[0m"

	output := colorable.NewColorableStdout()

	logo := "                             00000000000                                      \n" +
		"                           000000000000 00000000                              \n" +
		"                         0000000000000 0000000000                             \n" +
		"                       0000000000000 00000000000000                           \n" +
		"                     000000000      00000000000000000                         \n" +
		"                   0000000000                 000000000                       \n" +
		"                  0000000000        0000       0000000000                     \n" +
		"                 00000000000      000000        0000000000                    \n" +
		"                 00000000000      000000000     00000000000                   \n" +
		"                 00000000000      00000000      00000000000                   \n" +
		"                   0000000000       00000       00000000000                   \n" +
		"                     000000000                 0000000000                     \n" +
		"                       0000000000000          000000000                       \n" +
		"                        000000000000        0000000000                        \n" +
		"                          0000000000   0000000000000                          \n" +
		"                            00000000  000000000000                            \n" +
		"	    ____      _          ____        __                _           	 \n" +
		"	   / ___|   _| |__   ___|  _ \\  ___ / _| ___ _ __   __| |         	 \n" +
		"	  | |  | | | | '_ \\ / _ \\ | | |/ _ \\ |_ / _ \\ '_ \\ / _` |         \n" +
		"	  | |__| |_| | |_) |  __/ |_| |  __/  _|  __/ | | | (_| |          	 \n" +
		"	   \\____\\__, |_.__/ \\___|____/ \\___|_|  \\___|_| |_|\\__,_|        \n" +
		"		|___/                                                     	 \n"

	fmt.Fprint(output, color+"\n"+logo+reset+"\n")
}
