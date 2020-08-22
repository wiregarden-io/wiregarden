// Copyright 2020 Cmars Technologies LLC.
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.

package cli

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"syscall"

	"github.com/gosuri/uitable"
	"github.com/juju/zaputil/zapctx"
	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"
	"go.uber.org/zap/zapcore"
	"golang.org/x/crypto/ssh/terminal"

	"github.com/wiregarden-io/wiregarden/agent"
	"github.com/wiregarden-io/wiregarden/agent/store"
	"github.com/wiregarden-io/wiregarden/api"
)

var debug bool

var CommandLine = cli.App{
	Name: "wiregarden",
	Flags: []cli.Flag{
		&cli.PathFlag{Name: "datadir", Hidden: true},
		&cli.StringFlag{Name: "url", Hidden: true},
		&cli.BoolFlag{Name: "debug", Destination: &debug},
	},
	Commands: []*cli.Command{{
		Name: "up",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "name"},
			&cli.StringFlag{Name: "network"},
			&cli.StringFlag{Name: "endpoint"},
		},
		Action: func(c *cli.Context) error {
			if endpoint := c.String("endpoint"); endpoint != "" {
				_, _, err := net.SplitHostPort(endpoint)
				if err != nil {
					return errors.Wrap(err, "invalid endpoint, must be in the form host:port")
				}
			}
			a, err := agent.New(c.Path("datadir"), c.String("url"))
			if err != nil {
				return errors.WithStack(err)
			}
			token, err := GetToken("WIREGARDEN_SUBSCRIPTION", "Subscription")
			if err != nil {
				return errors.WithStack(err)
			}
			iface, err := a.JoinDevice(agent.WithToken(NewLoggerContext(), token), c.String("name"), c.String("network"), c.String("endpoint"))
			if err != nil {
				return errors.WithStack(err)
			}
			err = a.ApplyInterfaceChanges(iface)
			if err != nil {
				return errors.WithStack(err)
			}
			fmt.Printf("device %q joined network %q with address %q", iface.Device.Name, iface.Network.Name, iface.Device.Addr)
			return nil
		},
	}, {
		Name: "down",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "name"},
			&cli.StringFlag{Name: "network"},
		},
		Action: func(c *cli.Context) error {
			a, err := agent.New(c.Path("datadir"), c.String("url"))
			if err != nil {
				return errors.WithStack(err)
			}
			iface, err := a.DeleteDevice(NewLoggerContext(), c.String("name"), c.String("network"))
			if err != nil {
				return errors.WithStack(err)
			}
			err = a.ApplyInterfaceChanges(iface)
			if err != nil {
				return errors.WithStack(err)
			}
			fmt.Printf("device %q deleted from network %q", iface.Device.Name, iface.Network.Name)
			return errors.WithStack(err)
		},
	}, {
		Name: "refresh",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "name"},
			&cli.StringFlag{Name: "network"},
			&cli.StringFlag{Name: "endpoint"},
		},
		Action: func(c *cli.Context) error {
			if endpoint := c.String("endpoint"); endpoint != "" {
				_, _, err := net.SplitHostPort(endpoint)
				if err != nil {
					return errors.Wrap(err, "invalid endpoint, must be in the form host:port")
				}
			}
			a, err := agent.New(c.Path("datadir"), c.String("url"))
			if err != nil {
				return errors.WithStack(err)
			}
			if c.String("name") == "" && c.String("network") == "" && c.String("endpoint") == "" {
				ifaces, err := a.Interfaces()
				if err != nil {
					return errors.Wrap(err, "failed to list interfaces")
				}
				var lastErr error
				for i := range ifaces {
					iface, err := a.RefreshInterface(NewLoggerContext(), &ifaces[i])
					if err != nil {
						fmt.Printf("failed to refresh interface %q: %v", ifaces[i].Name(), err)
						lastErr = err
						continue
					}
					err = a.ApplyInterfaceChanges(iface)
					if err != nil {
						fmt.Printf("failed to apply changes to interface %q when refreshing: %v", ifaces[i].Name(), err)
						lastErr = err
						continue
					}
					fmt.Printf("device %q refreshed with latest network %q definition", iface.Device.Name, iface.Network.Name)
				}
				if ifaces, err = a.Interfaces(); err != nil {
					fmt.Printf("failed to list interfaces: %v", err)
				} else {
					printStatus(ifaces, false)
				}
				return lastErr
			}
			iface, err := a.RefreshDevice(NewLoggerContext(), c.String("name"), c.String("network"), c.String("endpoint"))
			if err != nil {
				return errors.WithStack(err)
			}
			err = a.ApplyInterfaceChanges(iface)
			if err != nil {
				return errors.WithStack(err)
			}
			fmt.Printf("device %q refreshed with latest network %q definition", iface.Device.Name, iface.Network.Name)
			return errors.WithStack(err)
		},
	}, {
		Name: "status",
		Flags: []cli.Flag{
			&cli.BoolFlag{Name: "json"},
		},
		Action: func(c *cli.Context) error {
			a, err := agent.New(c.Path("datadir"), c.String("url"))
			ifaces, err := a.Interfaces()
			if err != nil {
				return errors.WithStack(err)
			}
			printStatus(ifaces, c.Bool("json"))
			return nil
		},
	}, {
		Name:   "user",
		Hidden: true,
		Subcommands: []*cli.Command{{
			Name:    "get-subscription-token",
			Aliases: []string{"get-sub-token"},
			Flags: []cli.Flag{
				&cli.StringFlag{Name: "plan", Required: true},
			},
			Action: func(c *cli.Context) error {
				cl := api.New(c.String("url"))
				token, err := GetToken("WIREGARDEN_USER", "User")
				if err != nil {
					return errors.WithStack(err)
				}
				resp, err := cl.GetSubscriptionToken(agent.WithToken(NewLoggerContext(), token), c.String("plan"))
				if err != nil {
					return errors.WithStack(err)
				}
				return PrintJson(resp)
			},
		}},
	}},
}

func Run(cl *cli.App, args []string) {
	if cl == nil {
		cl = &CommandLine
	}
	syscall.Umask(0077)
	err := cl.Run(args)
	if err != nil {
		if debug {
			log.Fatalf("%+v", err)
		} else {
			log.Fatalf("%v", err)
		}
	}
}

func GetToken(key string, label string) ([]byte, error) {
	var err error
	token := os.Getenv(key)
	if token == "" {
		token, err = ReadPassword(label + " token: ")
		if err != nil {
			return nil, errors.Wrap(err, "failed to read token input")
		}
	}
	return base64.StdEncoding.DecodeString(token)
}

func NewLoggerContext() context.Context {
	level := zapcore.InfoLevel
	if debug {
		level = zapcore.DebugLevel
	}
	return zapctx.WithLevel(context.Background(), level)
}

func PrintJson(v interface{}) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	err := enc.Encode(v)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func ReadPassword(prompt string) (string, error) {
	fmt.Print(prompt)
	pass, err := terminal.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return "", errors.WithStack(err)
	}
	println()
	return string(pass), nil
}

func printStatus(ifaces []store.InterfaceWithLog, json bool) {
	if json {
		PrintJson(ifaces)
	}
	table := uitable.New()
	table.MaxColWidth = 50
	table.AddRow("Interface", "Network", "Address", "Port", "Peers", "Endpoint")
	for _, iface := range ifaces {
		table.AddRow(iface.Name, iface.Network.Name,
			iface.Device.Addr.String(), iface.ListenPort,
			len(iface.Peers), iface.Device.Endpoint)
	}
	fmt.Println(table)
	fmt.Println()
	for _, iface := range ifaces {
		table := uitable.New()
		table.MaxColWidth = 50
		table.AddRow("Network", "Peer", "Address", "Endpoint", "Key")
		table.AddRow(iface.Network.Name, iface.Device.Name+" (this host)",
			iface.Device.Addr.String(), iface.Device.Endpoint,
			iface.Device.PublicKey.String())
		for _, peer := range iface.Peers {
			table.AddRow(iface.Network.Name, peer.Name,
				peer.Addr.String(), peer.Endpoint, peer.PublicKey.String())
		}
		fmt.Println(table)
	}
}
