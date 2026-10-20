// identity-bridge validates configuration offline; it does not start a service.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/domainry/domainry-foundation/processhost"
	"github.com/domainry/domainry-identity-bridge/module/config"
)

func main() {
	os.Exit(run())
}

func run() int {
	path := flag.String("config", "", "configuration JSON file to validate")
	flag.Parse()
	if *path == "" || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: identity-bridge -config <file>")
		return 2
	}
	host, err := processhost.Open(context.Background(), processhost.Config{ServiceName: "domainry-identity-bridge"})
	if err != nil {
		return 1
	}
	host.Started(context.Background(), map[string]any{"mode": "configuration_validation"})
	file, err := os.Open(*path)
	if err != nil {
		if host.Finish(context.Background(), nil, errors.New("identity bridge configuration unavailable")) != nil {
			return 1
		}
		return 1
	}
	defer file.Close()
	if _, err := config.Load(file); err != nil {
		if host.Finish(context.Background(), nil, err) != nil {
			return 1
		}
		return 1
	}
	if err := host.Finish(context.Background(), map[string]any{"result": "valid"}, nil); err != nil {
		return 1
	}
	return 0
}
