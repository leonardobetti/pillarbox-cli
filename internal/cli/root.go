package cli

import (
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "pillarbox",
	Short: "Pillarbox encrypts and decrypts files from the terminal",
	Long: "Pillarbox encrypts and decrypts files and folders with age, " +
		"from the terminal, keyboard only.",
}

func init() {
	rootCmd.AddCommand(versionCmd)
}

// Execute runs the root command and exits with the process exit code.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(ExitOther)
	}
}
