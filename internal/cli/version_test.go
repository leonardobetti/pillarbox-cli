package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestVersionCommandPrintsVersion(t *testing.T) {
	buf := new(bytes.Buffer)
	versionCmd.SetOut(buf)
	defer versionCmd.SetOut(nil)

	if err := versionCmd.RunE(versionCmd, nil); err != nil {
		t.Fatalf("version command returned error: %v", err)
	}
	want := "pillarbox version " + Version
	if got := buf.String(); !strings.Contains(got, want) {
		t.Fatalf("output %q does not contain %q", got, want)
	}
}

func TestRootCommandHasVersionSubcommand(t *testing.T) {
	for _, c := range rootCmd.Commands() {
		if c.Name() == "version" {
			return
		}
	}
	t.Fatal("root command has no version subcommand")
}
