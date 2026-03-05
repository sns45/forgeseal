package main

import (
	"os"

	"github.com/sn45/forgeseal/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		os.Exit(1)
	}
}
