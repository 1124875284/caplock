// Command caplock discovers MCP servers and writes a deterministic capability
// lockfile.
package main

import (
	"os"

	"github.com/caplock/caplock/internal/cli"
)

func main() {
	os.Exit(cli.Execute(os.Args[1:], os.Stdout, os.Stderr))
}
