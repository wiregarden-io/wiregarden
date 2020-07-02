// Copyright 2020 Cmars Technologies LLC.
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.

package app

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log"
	"net"
	"os"
	"syscall"

	"github.com/juju/zaputil/zapctx"
	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"
	"go.uber.org/zap/zapcore"

	"github.com/wiregarden-io/wiregarden/client"
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
			a := New(c.Path("datadir"), c.String("url"))
			token, err := GetToken("WIREGARDEN_SUBSCRIPTION", "Subscription")
			if err != nil {
				return errors.WithStack(err)
			}
			err = a.Join(WithToken(NewLoggerContext(), token), c.String("name"), c.String("network"), c.String("endpoint"))
			return errors.WithStack(err)
		},
	}, {
		Name: "down",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "network"},
		},
		Action: func(c *cli.Context) error {
			a := New(c.Path("datadir"), c.String("url"))
			err := a.Depart(NewLoggerContext(), c.String("network"))
			return errors.WithStack(err)
		},
	}, {
		Name: "refresh",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "endpoint"},
		},
		Action: func(c *cli.Context) error {
			if endpoint := c.String("endpoint"); endpoint != "" {
				_, _, err := net.SplitHostPort(endpoint)
				if err != nil {
					return errors.Wrap(err, "invalid endpoint, must be in the form host:port")
				}
			}
			var err error
			a := New(c.Path("datadir"), c.String("url"))
			err = a.Refresh(NewLoggerContext(), c.String("endpoint"))
			return errors.WithStack(err)
		},
	}, {
		Name: "status",
		Action: func(c *cli.Context) error {
			a := New(c.Path("datadir"), c.String("url"))
			err := a.Status(NewLoggerContext())
			return errors.WithStack(err)
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
				cl := client.New(c.String("url"))
				token, err := GetToken("WIREGARDEN_USER", "User")
				if err != nil {
					return errors.WithStack(err)
				}
				resp, err := cl.GetSubscriptionToken(WithToken(NewLoggerContext(), token), c.String("plan"))
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
