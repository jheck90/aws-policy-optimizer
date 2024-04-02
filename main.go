package main

import (
	"github.com/jheck90/aws-policy-optimizer/cmd"
)

// version of aws-policy-optimizer. Overwritten during build
var version = "0.0.0"

func main() {
	cmd.Execute(version)
}
