package cli

import (
	"strings"

	"github.com/spf13/cobra"
)

func newExportKeyCmd(d *Deps) *cobra.Command {
	return &cobra.Command{
		Use:   "export-key <file.pbx>",
		Short: "Print the recovery key of one file after authentication",
		Args:  exactArgs(1, "usage: pillarbox export-key <file.pbx>"),
		RunE: func(cmd *cobra.Command, args []string) error {
			return d.runExportKey(args[0])
		},
	}
}

// runExportKey authenticates against the file's own key and prints its age
// identity, PRD 6.6.
func (d *Deps) runExportKey(src string) error {
	if !strings.HasSuffix(src, ".pbx") {
		return &exitError{ExitUsage, "export-key accepts a .pbx file only"}
	}
	ks, err := d.loadFileKey(src)
	if err != nil {
		return err
	}
	identityBytes, _, err := d.authenticate(ks)
	if err != nil {
		return err
	}
	d.println(string(identityBytes))
	return nil
}
