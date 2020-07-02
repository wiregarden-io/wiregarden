// Copyright 2020 Cmars Technologies LLC.
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.

package types_test

import (
	"encoding/json"
	"strings"
	"testing"

	qt "github.com/frankban/quicktest"

	"github.com/wiregarden-io/wiregarden/types"
)

func TestInvalidKey(t *testing.T) {
	c := qt.New(t)
	_, err := types.ParseKey("MAo=")
	c.Assert(err, qt.ErrorMatches, ".*invalid key length 2.*")
}

func TestInvalidAddress(t *testing.T) {
	c := qt.New(t)
	var addr types.Address
	err := addr.UnmarshalText([]byte("nope"))
	c.Assert(err, qt.ErrorMatches, ".*nope.*")
}

func TestMarshalAddress(t *testing.T) {
	c := qt.New(t)
	addr, err := types.ParseAddress("192.168.42.5/24")
	c.Assert(err, qt.IsNil)
	buf, err := json.Marshal(addr)
	c.Assert(err, qt.IsNil)
	c.Assert(string(buf), qt.Equals, `"192.168.42.5/24"`)

	doc := struct {
		Addr types.Address `json:"addr"`
		Port int           `json:"port"`
	}{
		Addr: *addr,
		Port: 31337,
	}
	buf, err = json.Marshal(&doc)
	c.Assert(err, qt.IsNil)
	c.Assert(string(buf), qt.Equals, `{"addr":"192.168.42.5/24","port":31337}`)
}

func TestSimple(t *testing.T) {
	c := qt.New(t)

	cfg := newSimpleConfig(c)
	c.Assert(`{
  "name": "guillermo",
  "address": "192.168.0.1/24",
  "privateKey": "`+cfg.PrivateKey.String()+`",
  "listenPort": 31313,
  "peers": [{
    "name": "nandor",
    "publicKey": "`+cfg.Peers[0].PublicKey.String()+`",
    "endpoint": "nandor.wiregarden.io:31313",
    "persistentKeepalive": 10
  }]
}`, qt.JSONEquals, cfg)

	var b strings.Builder
	err := cfg.WriteConfig(&b)
	c.Assert(err, qt.IsNil)
	c.Assert(b.String(), qt.Equals, `[Interface]
# Name = guillermo
Address = 192.168.0.1/24
ListenPort = 31313
PrivateKey = `+cfg.PrivateKey.String()+`

[Peer]
# Name = nandor
Endpoint = nandor.wiregarden.io:31313
PublicKey = `+cfg.Peers[0].PublicKey.String()+`
PersistentKeepalive = 10
`)
}

func TestComplete(t *testing.T) {
	c := qt.New(t)

	cfg := newCompleteConfig(c)
	c.Assert(`{
  "name": "laszlo",
  "address": "10.11.12.13/8",
  "listenPort": 31313,
  "privateKey": "`+cfg.PrivateKey.String()+`",
  "dns": ["1.1.1.1", "8.8.8.8", "9.9.9.9"],
  "table": "auto",
  "mtu": 1500,
  "preUp": "echo preup",
  "preDown": "echo predown",
  "postUp": "echo postup",
  "postDown": "echo postdown",
  "peers": [{
    "name": "nadja",
    "endpoint": "nadja.wiregarden.io:31314",
    "allowedIPs": ["0.0.0.0/0"],
    "publicKey": "`+cfg.Peers[0].PublicKey.String()+`",
    "persistentKeepalive": 10
  },{
    "name": "colin",
    "endpoint": "colin.wiregarden.io:31315",
    "allowedIPs": ["123.45.67.89/32"],
    "publicKey": "`+cfg.Peers[1].PublicKey.String()+`",
    "persistentKeepalive": 20
  }]
}`, qt.JSONEquals, cfg)

	var b strings.Builder
	err := cfg.WriteConfig(&b)
	c.Assert(err, qt.IsNil)
	c.Assert(b.String(), qt.Equals, `[Interface]
# Name = laszlo
Address = 10.11.12.13/8
ListenPort = 31313
PrivateKey = `+cfg.PrivateKey.String()+`
DNS = 1.1.1.1,8.8.8.8,9.9.9.9
Table = auto
MTU = 1500
PreUp = echo preup
PreDown = echo predown
PostUp = echo postup
PostDown = echo postdown

[Peer]
# Name = nadja
AllowedIPs = 0.0.0.0/0
Endpoint = nadja.wiregarden.io:31314
PublicKey = `+cfg.Peers[0].PublicKey.String()+`
PersistentKeepalive = 10

[Peer]
# Name = colin
AllowedIPs = 123.45.67.89/32
Endpoint = colin.wiregarden.io:31315
PublicKey = `+cfg.Peers[1].PublicKey.String()+`
PersistentKeepalive = 20
`)
}

func newSimpleConfig(c *qt.C) *types.InterfaceConfig {
	cfg := &types.InterfaceConfig{
		Name:       "guillermo",
		Address:    assertNewAddress(c, "192.168.0.1/24"),
		PrivateKey: assertGenerateKey(c),
		ListenPort: 31313,
		Peers: []types.PeerConfig{{
			Name:                "nandor",
			PublicKey:           assertGenerateKey(c).PublicKey(),
			Endpoint:            "nandor.wiregarden.io:31313",
			PersistentKeepalive: 10,
		}},
	}
	return cfg
}

func assertGenerateKey(c *qt.C) types.Key {
	k, err := types.GenerateKey()
	c.Assert(err, qt.IsNil)
	return k
}

func assertNewAddress(c *qt.C, s string) types.Address {
	addr, err := types.ParseAddress(s)
	c.Assert(err, qt.IsNil)
	return *addr
}

func newCompleteConfig(c *qt.C) *types.InterfaceConfig {
	peerKey1 := assertGenerateKey(c)
	peerKey2 := assertGenerateKey(c)

	cfg := &types.InterfaceConfig{
		Name:       "laszlo",
		Address:    assertNewAddress(c, "10.11.12.13/8"),
		ListenPort: 31313,
		PrivateKey: assertGenerateKey(c),
		DNS:        []string{"1.1.1.1", "8.8.8.8", "9.9.9.9"},
		Table:      "auto",
		MTU:        1500,
		PreUp:      "echo preup",
		PreDown:    "echo predown",
		PostUp:     "echo postup",
		PostDown:   "echo postdown",
		Peers: []types.PeerConfig{{
			Name:     "nadja",
			Endpoint: "nadja.wiregarden.io:31314",
			AllowedIPs: []types.Address{
				assertNewAddress(c, "0.0.0.0/0"),
			},
			PublicKey:           peerKey1.PublicKey(),
			PersistentKeepalive: 10,
		}, {
			Name:     "colin",
			Endpoint: "colin.wiregarden.io:31315",
			AllowedIPs: []types.Address{
				assertNewAddress(c, "123.45.67.89/32"),
			},
			PublicKey:           peerKey2.PublicKey(),
			PersistentKeepalive: 20,
		}},
	}
	return cfg
}
