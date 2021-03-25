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
	stdlog "log"
	"net"
	"os"
	"sort"
	"syscall"

	"github.com/google/uuid"
	"github.com/gosuri/uitable"
	"github.com/juju/zaputil/zapctx"
	"github.com/nightlyone/lockfile"
	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"
	"go.uber.org/multierr"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh/terminal"

	"github.com/wiregarden-io/wiregarden/agent"
	"github.com/wiregarden-io/wiregarden/agent/store"
	"github.com/wiregarden-io/wiregarden/api"
	"github.com/wiregarden-io/wiregarden/daemon"
	"github.com/wiregarden-io/wiregarden/log"
	"github.com/wiregarden-io/wiregarden/setup"
)

var debug bool

var version string = "development"

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
			&cli.StringFlag{Name: "network", Aliases: []string{"net"}},
			&cli.StringFlag{Name: "endpoint"},
			&cli.StringFlag{Name: "address", Aliases: []string{"addr"}},
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
			iface, err := a.JoinDevice(agent.WithToken(ctx, token), agent.JoinArgs{
				Name:     c.String("name"),
				Network:  c.String("network"),
				Endpoint: c.String("endpoint"),
				Address:  c.String("address"),
			})
			if err != nil {
				return errors.WithStack(err)
			}
			err = a.ApplyInterfaceChanges(ctx, iface)
			if err != nil {
				return errors.WithStack(err)
			}
			zapctx.Info(ctx, "up",
				zap.String("device", iface.Device.Name),
				zap.String("network", iface.Network.Name),
				zap.String("address", iface.Device.Addr.String()))
			return nil
		},
	}, {
		Name: "down",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "name"},
			&cli.StringFlag{Name: "network", Aliases: []string{"net"}},
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
			err = a.ApplyInterfaceChanges(ctx, iface)
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
			&cli.StringFlag{Name: "network", Aliases: []string{"net"}},
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
					if ifaces[i].Log.State == store.StateInterfaceDown {
						continue
					}
					iface, err := a.RefreshInterface(ctx, &ifaces[i], "")
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
					err = a.ApplyInterfaceChanges(ctx, iface)
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
			iface, err := a.RefreshDevice(ctx, agent.JoinArgs{
				Name:     c.String("name"),
				Network:  c.String("network"),
				Endpoint: c.String("endpoint"),
			})
			if err != nil {
				return errors.WithStack(err)
			}
			err = a.ApplyInterfaceChanges(ctx, iface)
			if err != nil {
				return errors.WithStack(err)
			}
			zapctx.Info(ctx, "refreshed",
				zap.String("device", iface.Device.Name),
				zap.String("network", iface.Network.Name))
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
			return nil
		},
	}, {
		Name: "setup",
		Flags: []cli.Flag{
			&cli.BoolFlag{Name: "nss-plugin", Value: true},
		},
		Action: func(c *cli.Context) error {
			if os.Getuid() != 0 {
				return errors.New("must be run as root")
			}
			ctx := NewLoggerContext(c)
			var merr []error
			err := setup.EnsureWireguardInstalled(ctx)
			if err != nil {
				merr = append(merr, err)
				fmt.Println(setup.ManualPackageInstructions)
			}
			if c.Bool("nss-plugin") {
				err = setup.EnsureNssPluginInstalled(ctx)
				if errors.Is(err, setup.ErrUnsupportedPlatform) {
					fmt.Println(setup.ManualNssInstructions)
				} else if err != nil {
					merr = append(merr, err)
				}
			}
			err = daemon.Install()
			if err != nil {
				merr = append(merr, err)
				fmt.Println(daemon.FailedServiceNotice)
			}
			if len(merr) > 0 {
				fmt.Println("There were errors during the installation:")
			}
			return multierr.Combine(merr...)
		},
	}, {
		Name:   "daemon",
		Hidden: true,
		Subcommands: []*cli.Command{{
			Name:  "run",
			Flags: []cli.Flag{},
			Action: func(c *cli.Context) error {
				if os.Getuid() != 0 {
					return errors.New("must be run as root")
				}
				lf, err := lockfile.New(agent.WatcherLockPath())
				if err != nil {
					return errors.Wrap(err, "failed to create lock file handle")
				}
				if err := lf.TryLock(); err != nil {
					return errors.Wrap(err, "failed to obtain lock file")
				}
				a, err := agent.New(c.Path("datadir"), c.String("url"))
				if err != nil {
					return errors.Wrap(err, "failed to create agent")
				}
				w := daemon.New(a)
				ctx := NewLoggerContext(c)
				err = w.Start(ctx)
				if err != nil {
					return errors.Wrap(err, "failed to start daemon")
				}
				<-ctx.Done()
				w.Shutdown(ctx)
				return nil
			},
		}, {
			Name:  "install",
			Flags: []cli.Flag{},
			Action: func(c *cli.Context) error {
				if os.Getuid() != 0 {
					return errors.New("must be run as root")
				}
				return errors.WithStack(daemon.Install())
			},
		}, {
			Name:  "uninstall",
			Flags: []cli.Flag{},
			Action: func(c *cli.Context) error {
				if os.Getuid() != 0 {
					return errors.New("must be run as root")
				}
				ctx := NewLoggerContext(c)
				return errors.WithStack(daemon.Uninstall(ctx))
			},
		}},
	}, {
		Name: "devices",
		Subcommands: []*cli.Command{{
			Name: "list",
			Action: func(c *cli.Context) error {
				cl := api.New(c.String("url"))
				token, err := GetToken("WIREGARDEN_SUBSCRIPTION", "Subscription")
				if err != nil {
					return errors.WithStack(err)
				}
				resp, err := cl.ListDevices(agent.WithToken(NewLoggerContext(c), token))
				if err != nil {
					return errors.WithStack(err)
				}
				return PrintJson(resp)
			},
		}, {
			Name: "delete",
			Flags: []cli.Flag{
				&cli.StringFlag{Name: "device"},
				&cli.StringFlag{Name: "network"},
			},
			Action: func(c *cli.Context) error {
				if (c.String("device") == "") == (c.String("network") == "") {
					return errors.New("specify one of --device or --network options")
				}
				cl := api.New(c.String("url"))
				token, err := GetToken("WIREGARDEN_SUBSCRIPTION", "Subscription")
				if err != nil {
					return errors.WithStack(err)
				}
				if device := c.String("device"); device != "" {
					if _, err := uuid.Parse(device); err != nil {
						return errors.Wrap(err, "invalid device id")
					}
					err = cl.DeleteDevice(agent.WithToken(NewLoggerContext(c), token), device)
				} else if network := c.String("network"); network != "" {
					if _, err := uuid.Parse(network); err != nil {
						return errors.Wrap(err, "invalid network id")
					}
					err = cl.DeleteNetwork(agent.WithToken(NewLoggerContext(c), token), network)
				}
				return errors.WithStack(err)
			},
		}},
	}, {
		Name: "version",
		Action: func(c *cli.Context) error {
			fmt.Println(version)
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
		}, {
			Name:    "list-subscriptions",
			Aliases: []string{"list-subs"},
			Action: func(c *cli.Context) error {
				cl := api.New(c.String("url"))
				token, err := GetToken("WIREGARDEN_USER", "User")
				if err != nil {
					return errors.WithStack(err)
				}
				resp, err := cl.ListSubscriptions(agent.WithToken(NewLoggerContext(c), token))
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
			stdlog.Fatalf("%+v", err)
		} else {
			stdlog.Fatalf("%v", err)
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
	return log.WithLog(context.Background(), debug)
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

type sortedInterfaces []store.InterfaceWithLog

func (si sortedInterfaces) Len() int      { return len(si) }
func (si sortedInterfaces) Swap(i, j int) { si[i], si[j] = si[j], si[i] }
func (si sortedInterfaces) Less(i, j int) bool {
	return si[i].Network.Name+si[i].Device.Name < si[j].Network.Name+"."+si[j].Device.Name
}

type sortedPeers []api.Device

func (sp sortedPeers) Len() int      { return len(sp) }
func (sp sortedPeers) Swap(i, j int) { sp[i], sp[j] = sp[j], sp[i] }
func (sp sortedPeers) Less(i, j int) bool {
	return sp[i].Id < sp[j].Id
}

func printStatus(ifaces []store.InterfaceWithLog, json, down bool) {
	sort.Sort(sortedInterfaces(ifaces))
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
		table.AddRow("Peer", "Address", "Endpoint", "Key")
		table.AddRow(iface.Device.Name+"."+iface.Network.Name+" (this host)",
			iface.Device.Addr.IP.String(), iface.Device.Endpoint,
			iface.Device.PublicKey.String())
		sort.Sort(sortedPeers(iface.Peers))
		for _, peer := range iface.Peers {
			table.AddRow(peer.Name+"."+iface.Network.Name,
				peer.Addr.IP.String(), peer.Endpoint, peer.PublicKey.String())
		}
		fmt.Println(table)
	}
}
