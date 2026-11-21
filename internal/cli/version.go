package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

// Version is the pillarbox version. The Makefile overrides it with ldflags.
var Version = "0.1.0"

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the pillarbox version",
		Args:  exactArgs(0, "usage: pillarbox version"),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := fmt.Fprintf(cmd.OutOrStdout(), "pillarbox version %s\n", Version)
			return err
		},
	}
}
