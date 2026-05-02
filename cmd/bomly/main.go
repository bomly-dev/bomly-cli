package main

import (
	"fmt"
	"os"

	"github.com/bomly-dev/bomly-cli/internal/cli"
)

var version = "0.1.0"

func main() {
	if err := cli.Execute(version); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "\n\n%s: %v", cli.ErrorPrefix(err), err)
		os.Exit(cli.ExitCode(err))
	}
}
