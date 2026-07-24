package main

import (
	"fmt"
	"os"

	"github.com/bomly-dev/bomly-cli/internal/cli"
	"github.com/bomly-dev/bomly-cli/internal/cli/exit"
)

var version = "0.20.0"

func main() {
	if err := cli.Execute(version); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "\n\n%s: %v\n", exit.ErrorPrefix(err), err)
		os.Exit(exit.Code(err))
	}
}
