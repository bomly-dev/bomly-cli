package main

import (
	"fmt"
	"os"

	"github.com/bomly/bomly-cli/internal/cli"
)

var version = "0.1.0"

func main() {
	if err := cli.Execute(version); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(cli.ExitCode(err))
	}
}
