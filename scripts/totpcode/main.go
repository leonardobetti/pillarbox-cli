// Command totpcode prints the current RFC 6238 TOTP code for a base32 seed.
// It exists only for scripts/e2e.sh, which needs a valid code for 2FA modes
// in non-interactive runs.
package main

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/pquerna/otp/totp"
)

func main() {
	if len(os.Args) < 2 || len(os.Args) > 3 {
		fmt.Fprintln(os.Stderr, "usage: totpcode <base32-seed> [step-offset]")
		os.Exit(2)
	}
	t := time.Now()
	if len(os.Args) == 3 {
		off, err := strconv.Atoi(os.Args[2])
		if err != nil {
			fmt.Fprintln(os.Stderr, "totpcode: bad offset:", err)
			os.Exit(2)
		}
		t = t.Add(time.Duration(off) * 30 * time.Second)
	}
	code, err := totp.GenerateCode(os.Args[1], t)
	if err != nil {
		fmt.Fprintln(os.Stderr, "totpcode:", err)
		os.Exit(1)
	}
	fmt.Println(code)
}
