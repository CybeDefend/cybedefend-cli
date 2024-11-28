// File: cmd/root.go

package cmd

import (
	"fmt"
	"os"

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
)

var rootCmd = &cobra.Command{
	Use:   "cybedefend",
	Short: "CybeDefend CLI for interacting with the CybeDefend API",
	Long:  `CybeDefend CLI is a CLI tool to interact with the CybeDefend API.`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Load configuration
		var err error
		config, err = utils.LoadConfig()
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
	rootCmd.PersistentFlags().String("api-url", "https://api.cybedefend.com", "API URL")
	rootCmd.PersistentFlags().String("api-key", "", "API Key")
	rootCmd.PersistentFlags().Bool("ci", false, "CI mode")
	rootCmd.PersistentFlags().Bool("debug", false, "Debug mode")
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "Config file (default is $HOME/.cybedefend/config.yaml) (optional)")

	// Bind flags to Viper
	viper.BindPFlag("api_url", rootCmd.PersistentFlags().Lookup("api-url"))
	viper.BindPFlag("api_key", rootCmd.PersistentFlags().Lookup("api-key"))
	viper.BindPFlag("ci", rootCmd.PersistentFlags().Lookup("ci"))
	viper.BindPFlag("debug", rootCmd.PersistentFlags().Lookup("debug"))

	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(resultsCmd)
	rootCmd.AddCommand(versionCmd)
}

func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	}

	viper.SetConfigName("config")            // Name of config file (without extension)
	viper.SetConfigType("yaml")              // REQUIRED if the config file does not have the extension in the name
	viper.AddConfigPath(".")                 // Look for config in the current directory
	viper.AddConfigPath("$HOME/.cybedefend") // Optionally look for config in the user's home directory
	viper.AddConfigPath("/etc/cybedefend/")  // Optionally look for config in /etc/cybedefend/

	// Read in environment variables that match
	viper.SetEnvPrefix("CYBEDEFEND")
	viper.AutomaticEnv()

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		isUsingConfigFile = true
	}
}

// displayBanner prints the ASCII art banner
func displayBanner() {
	// Define the ANSI color code for RGB(40,20,52)
	color := "\033[38;2;40;20;52m"
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
