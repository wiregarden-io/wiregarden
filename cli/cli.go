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
	"os/exec"
	"syscall"

	"github.com/gosuri/uitable"
	"github.com/juju/zaputil/zapctx"
	"github.com/nightlyone/lockfile"
	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/crypto/ssh/terminal"

	"github.com/wiregarden-io/wiregarden/agent"
	"github.com/wiregarden-io/wiregarden/agent/store"
	"github.com/wiregarden-io/wiregarden/api"
	"github.com/wiregarden-io/wiregarden/watcher"
)

var debug bool

var CommandLine = cli.App{
	Name: "wiregarden",
	Flags: []cli.Flag{
		&cli.PathFlag{Name: "datadir", Hidden: true},
		&cli.StringFlag{Name: "url", Hidden: true},
		&cli.BoolFlag{Name: "debug", Hidden: true, Destination: &debug},
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
			a, err := agent.New(c.Path("datadir"), c.String("url"), agent.NotifyWatcher)
			if err != nil {
				return errors.WithStack(err)
			}
			token, err := GetToken("WIREGARDEN_SUBSCRIPTION", "Subscription")
			if err != nil {
				return errors.WithStack(err)
			}
			ctx := NewLoggerContext(c)
			iface, err := a.JoinDevice(agent.WithToken(ctx, token), c.String("name"), c.String("network"), c.String("endpoint"))
			if err != nil {
				return errors.WithStack(err)
			}
			err = a.ApplyInterfaceChanges(iface)
			if err != nil {
				return errors.WithStack(err)
			}
			zapctx.Info(ctx, "up",
				zap.String("device", iface.Device.Name),
				zap.String("network", iface.Network.Name),
				zap.String("address", iface.Device.Addr.String()))
			ensureWatcherLaunch()
			return nil
		},
	}, {
		Name: "down",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "name"},
			&cli.StringFlag{Name: "network"},
		},
		Action: func(c *cli.Context) error {
			a, err := agent.New(c.Path("datadir"), c.String("url"), agent.NotifyWatcher)
			if err != nil {
				return errors.WithStack(err)
			}
			ctx := NewLoggerContext(c)
			iface, err := a.DeleteDevice(ctx, c.String("name"), c.String("network"))
			if err != nil {
				return errors.WithStack(err)
			}
			err = a.ApplyInterfaceChanges(iface)
			if err != nil {
				return errors.WithStack(err)
			}
			zapctx.Info(ctx, "down",
				zap.String("device", iface.Device.Name),
				zap.String("network", iface.Network.Name))
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
			a, err := agent.New(c.Path("datadir"), c.String("url"), agent.NotifyWatcher)
			if err != nil {
				return errors.WithStack(err)
			}
			ctx := NewLoggerContext(c)
			if c.String("name") == "" && c.String("network") == "" && c.String("endpoint") == "" {
				ifaces, err := a.Interfaces()
				if err != nil {
					return errors.Wrap(err, "failed to list interfaces")
				}
				var lastErr error
				for i := range ifaces {
					iface, err := a.RefreshInterface(ctx, &ifaces[i])
					if err != nil {
						zapctx.Warn(ctx, "refresh failed",
							zap.String("interface", ifaces[i].Name()),
							zap.String("device", ifaces[i].Device.Name),
							zap.String("network", ifaces[i].Network.Name),
							zap.Error(err),
						)
						lastErr = err
						continue
					}
					err = a.ApplyInterfaceChanges(iface)
					if err != nil {
						zapctx.Warn(ctx, "failed to apply interface changes",
							zap.String("interface", ifaces[i].Name()),
							zap.String("device", ifaces[i].Device.Name),
							zap.String("network", ifaces[i].Network.Name),
							zap.Error(err),
						)
						lastErr = err
						continue
					}
					zapctx.Info(ctx, "refreshed",
						zap.String("device", iface.Device.Name),
						zap.String("network", iface.Network.Name))
				}
				if ifaces, err = a.Interfaces(); err != nil {
					zapctx.Warn(ctx, "failed to list interfaces", zap.Error(err))
				} else {
					printStatus(ifaces, false, false)
				}
				return lastErr
			}
			iface, err := a.RefreshDevice(ctx, c.String("name"), c.String("network"), c.String("endpoint"))
			if err != nil {
				return errors.WithStack(err)
			}
			err = a.ApplyInterfaceChanges(iface)
			if err != nil {
				return errors.WithStack(err)
			}
			zapctx.Info(ctx, "refreshed",
				zap.String("device", iface.Device.Name),
				zap.String("network", iface.Network.Name))
			ensureWatcherLaunch()
			return nil
		},
	}, {
		Name: "status",
		Flags: []cli.Flag{
			&cli.BoolFlag{Name: "json"},
			&cli.BoolFlag{Name: "down"},
		},
		Action: func(c *cli.Context) error {
			a, err := agent.New(c.Path("datadir"), c.String("url"))
			if err != nil {
				return errors.WithStack(err)
			}
			ifaces, err := a.Interfaces()
			if err != nil {
				return errors.WithStack(err)
			}
			printStatus(ifaces, c.Bool("json"), c.Bool("down"))
			ensureWatcherLaunch()
			return nil
		},
	}, {
		Name:   "watcher",
		Hidden: true,
		Flags:  []cli.Flag{},
		Action: func(c *cli.Context) error {
			lf, err := lockfile.New(agent.WatcherLockPath())
			if err != nil {
				return errors.WithStack(err)
			}
			if err := lf.TryLock(); err != nil {
				return errors.WithStack(err)
			}
			a, err := agent.New(c.Path("datadir"), c.String("url"))
			if err != nil {
				return errors.WithStack(err)
			}
			w := watcher.New(a)
			ctx := NewLoggerContext(c)
			err = w.Start(ctx)
			if err != nil {
				return errors.WithStack(err)
			}
			<-chan struct{}(nil)
			w.Wait(ctx)
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
				resp, err := cl.GetSubscriptionToken(agent.WithToken(NewLoggerContext(c), token), c.String("plan"))
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

func NewLoggerContext(c *cli.Context) context.Context {
	if debug {
		zapctx.LogLevel.SetLevel(zapcore.DebugLevel)
	}
	return zapctx.WithLogger(context.Background(), zapctx.Default)
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

func printStatus(ifaces []store.InterfaceWithLog, json, down bool) {
	if json {
		PrintJson(ifaces)
	}
	table := uitable.New()
	table.MaxColWidth = 50
	table.AddRow("Interface", "Network", "Address", "Port", "Peers", "Status")
	for _, iface := range ifaces {
		if iface.Log.State == store.StateInterfaceDown && !down {
			continue
		}
		table.AddRow(iface.Name(), iface.Network.Name,
			iface.Device.Addr.String(), iface.ListenPort,
			len(iface.Peers), iface.Log.State)
	}
	fmt.Println(table)
	for _, iface := range ifaces {
		if iface.Log.State == store.StateInterfaceDown && !down {
			continue
		}
		fmt.Println()
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

func ensureWatcherLaunch() {
	cmd := exec.Command(os.Args[0], "watcher")
	if err := cmd.Start(); err == nil {
		cmd.Process.Release()
	}
}
