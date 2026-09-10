// identity-bridge validates configuration offline; it does not start a service.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/domainry/domainry-identity-bridge/config"
)

func main() {
	path := flag.String("config", "", "configuration JSON file to validate")
	flag.Parse()
	if *path == "" || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: identity-bridge -config <file>")
		os.Exit(2)
	}
	file, err := os.Open(*path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot open configuration")
		os.Exit(1)
	}
	defer file.Close()
	if _, err := config.Load(file); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("configuration valid; no provider contacted and no workspace created")
}
