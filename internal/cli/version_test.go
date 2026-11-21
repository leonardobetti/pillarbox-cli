package cli

import (
	"strings"
	"testing"
)

func TestVersionCommandPrintsVersion(t *testing.T) {
	e := newEnv(t)
	code, out, errOut := e.run(t, "", "version")
	if code != ExitOK {
		t.Fatalf("exit = %d, stderr %q", code, errOut)
	}
	if !strings.Contains(out, "pillarbox version "+Version) {
		t.Fatalf("stdout = %q, want it to contain %q", out, "pillarbox version "+Version)
	}
}
