package main

import (
	"os"

	"github.com/HodeTech/leakwatch/cmd"
)

// Build bilgileri (ldflags ile enjekte edilir).
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	cmd.SetVersionInfo(version, commit, date)
	os.Exit(cmd.Execute())
}
