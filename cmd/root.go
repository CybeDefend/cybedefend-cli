// File: cmd/root.go

package cmd

import (
	"fmt"
	"os"

	"cybedefend-cli/pkg/utils"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile string
	config  *utils.Config
)

var rootCmd = &cobra.Command{
	Use:   "cybedefend",
	Short: "CybeDefend CLI for interacting with the CybeDefend API",
	Long:  `CybeDefend is a CLI tool to interact with the CybeDefend API.`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Load configuration
		var err error
		config, err = utils.LoadConfig()
		if err != nil {
			return err
		}
		return nil
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	// Global flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.cybedefend/config.yaml)")
	rootCmd.PersistentFlags().String("api-url", "", "API URL")
	rootCmd.PersistentFlags().String("api-key", "", "API Key")

	// Bind flags to Viper
	viper.BindPFlag("api_url", rootCmd.PersistentFlags().Lookup("api-url"))
	viper.BindPFlag("api_key", rootCmd.PersistentFlags().Lookup("api-key"))

	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(resultsCmd)
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(helpCmd)
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
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}
}
