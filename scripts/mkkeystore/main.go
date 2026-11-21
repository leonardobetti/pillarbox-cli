// Command mkkeystore creates a pillarbox keystore non-interactively, reading
// the secret from stdin. It exists only for scripts/e2e.sh, because the CLI
// no longer exposes an init command: setup happens through bare pillarbox.
// The keystore lands in the standard config dir (HOME/XDG_CONFIG_HOME), the
// recovery key is printed to stdout, and no secret appears in argv.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"

	"filippo.io/age"

	"github.com/leonardobetti/pillarbox-cli/internal/auth"
	"github.com/leonardobetti/pillarbox-cli/internal/keystore"
)

func main() {
	modeStr := flag.String("mode", string(keystore.ModePassword), "unlock mode: password, pin, password+2fa, pin+2fa")
	flag.Parse()
	m := keystore.Mode(*modeStr)
	if !m.Valid() {
		fmt.Fprintln(os.Stderr, "mkkeystore: invalid mode")
		os.Exit(2)
	}

	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, "mkkeystore: cannot read secret from stdin")
		os.Exit(1)
	}
	secret := bytes.TrimRight(data, "\r\n")
	if err := auth.ValidateSecret(m, secret); err != nil {
		fmt.Fprintln(os.Stderr, "mkkeystore: invalid secret:", err)
		os.Exit(2)
	}

	var devSecret []byte
	if m.HasDeviceSecret() {
		devPath, err := auth.DefaultDeviceSecretPath()
		if err != nil {
			fmt.Fprintln(os.Stderr, "mkkeystore: cannot resolve config dir")
			os.Exit(1)
		}
		devSecret, _, err = auth.NewDeviceSecretStore(devPath).LoadOrCreate()
		if err != nil {
			fmt.Fprintln(os.Stderr, "mkkeystore: cannot write device secret")
			os.Exit(1)
		}
	}

	identity, err := age.GenerateX25519Identity()
	if err != nil {
		fmt.Fprintln(os.Stderr, "mkkeystore: cannot generate identity")
		os.Exit(1)
	}

	var seed []byte
	if m.Has2FA() {
		if s := os.Getenv("PILLARBOX_E2E_TOTP_SEED"); s != "" {
			seed, _, err = auth.GenerateSeedFromBase32(s)
		} else {
			seed, _, err = auth.NewTOTP().GenerateSeed()
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "mkkeystore: cannot generate TOTP seed")
			os.Exit(1)
		}
	}

	ks, err := auth.NewInitializer(auth.NewKDF(), keystore.NewWrapper()).Initialize(
		m, identity.Recipient().String(), []byte(identity.String()), secret, devSecret, seed, keystore.DefaultArgon2Params)
	if err != nil {
		fmt.Fprintln(os.Stderr, "mkkeystore: cannot build keystore")
		os.Exit(1)
	}
	store, err := keystore.DefaultStore()
	if err != nil {
		fmt.Fprintln(os.Stderr, "mkkeystore: cannot resolve config dir")
		os.Exit(1)
	}
	if err := store.Save(ks); err != nil {
		fmt.Fprintln(os.Stderr, "mkkeystore: cannot write keystore")
		os.Exit(1)
	}
	fmt.Println(identity.String())
}
