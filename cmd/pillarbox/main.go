// Command pillarbox is the Pillarbox CLI entry point.
package main

import (
	"os"

	"github.com/leonardobetti/pillarbox-cli/internal/cli"
)

func main() {
	os.Exit(cli.Execute())
}
