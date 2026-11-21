package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

// Version is the pillarbox version. The Makefile overrides it with ldflags.
var Version = "0.1.0"

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the pillarbox version",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		_, err := fmt.Fprintf(cmd.OutOrStdout(), "pillarbox version %s\n", Version)
		return err
	},
}
