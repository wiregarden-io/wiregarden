// Copyright 2020 Cmars Technologies LLC.
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.

// Package wireguard models wireguard device configuration.
package wireguard

import (
	"encoding/base64"
	"io"
	"net"
	"strconv"
	"strings"
	"text/template"

	"github.com/pkg/errors"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// InterfaceConfig represents a wireguard config file for a network interface.
// See https://github.com/pirate/wireguard-docs#Config-Reference for more
// information.
type InterfaceConfig struct {
	Name       string       `json:"name,omitempty"`
	Address    Address      `json:"address,omitempty"`
	ListenPort int          `json:"listenPort,omitempty"`
	PrivateKey Key          `json:"privateKey,omitempty"`
	DNS        []string     `json:"dns,omitempty"`
	Table      string       `json:"table,omitempty"`
	MTU        int          `json:"mtu,omitempty"`
	PreUp      string       `json:"preUp,omitempty"`
	PostUp     string       `json:"postUp,omitempty"`
	PreDown    string       `json:"preDown,omitempty"`
	PostDown   string       `json:"postDown,omitempty"`
	Peers      []PeerConfig `json:"peers,omitempty"`
}

func (c *InterfaceConfig) WriteConfig(w io.Writer) error {
	return deviceTmpl.Execute(w, c)
}

func (c *InterfaceConfig) RenderConfig() string {
	var b strings.Builder
	err := c.WriteConfig(&b)
	if err != nil {
		panic(err)
	}
	return b.String()
}

var deviceTmpl = template.Must(template.New("device").Parse(`
[Interface]
# Name = {{.Name}}
Address = {{.Address}}
ListenPort = {{.ListenPort}}
PrivateKey = {{.PrivateKey}}
{{- if .DNS }}
DNS = {{ range $i, $dns := .DNS -}}{{- if (gt $i  0) -}},{{- end -}}{{ $dns }}{{- end }}
{{- end }}
{{- if .Table }}
Table = {{ .Table }}
{{- end }}
{{- if .MTU }}
MTU = {{ .MTU }}
{{- end }}
{{- if .PreUp }}
PreUp = {{ .PreUp }}
{{- end }}
{{- if .PreDown }}
PreDown = {{ .PreDown }}
{{- end }}
{{- if .PostUp }}
PostUp = {{ .PostUp }}
{{- end }}
{{- if .PostDown }}
PostDown = {{ .PostDown }}
{{- end }}
{{- range $peer := .Peers }}

{{ $peer.RenderConfig }}
{{- end }}
`[1:]))

type Key []byte

func GenerateKey() (Key, error) {
	wgKey, err := wgtypes.GenerateKey()
	if err != nil {
		return nil, err
	}
	return Key(wgKey[:wgtypes.KeyLen]), nil
}

func (k Key) PublicKey() Key {
	var wgKey wgtypes.Key
	copy(wgKey[:wgtypes.KeyLen], k[:wgtypes.KeyLen])
	pub := wgKey.PublicKey()
	return Key(pub[:wgtypes.KeyLen])
}

func (k Key) String() string { return base64.StdEncoding.EncodeToString(k[:]) }

func (k Key) MarshalText() ([]byte, error) {
	return []byte(k.String()), nil
}

func (k *Key) UnmarshalText(data []byte) error {
	key, err := ParseKey(string(data))
	if err != nil {
		return err
	}
	*k = key
	return nil
}

func ParseKey(s string) (Key, error) {
	buf, err := base64.StdEncoding.DecodeString(string(s))
	if err != nil {
		return nil, err
	}
	if len(buf) < wgtypes.KeyLen {
		return nil, errors.Errorf("invalid key length %d", len(buf))
	}
	return Key(buf[:wgtypes.KeyLen]), nil
}

type Address net.IPNet

func (a Address) MarshalText() ([]byte, error) {
	return []byte(a.String()), nil
}

func (a Address) MarshalJSON() ([]byte, error) {
	text, err := a.MarshalText()
	if err != nil {
		return nil, err
	}
	return []byte(`"` + string(text) + `"`), nil
}

func (a *Address) String() string {
	size, _ := a.Mask.Size()
	return a.IP.String() + "/" + strconv.Itoa(size)
}

func (a *Address) UnmarshalText(data []byte) error {
	addr, err := ParseAddress(string(data))
	if err != nil {
		return err
	}
	*a = *addr
	return nil
}

func (a *Address) CIDR() *net.IPNet {
	ipNet := net.IPNet{IP: a.IP.To4(), Mask: a.Mask}
	for i := 0; i < 4; i++ {
		ipNet.IP[i] &= ipNet.Mask[i]
	}
	return &ipNet
}

func ParseAddress(s string) (*Address, error) {
	ip, ipNet, err := net.ParseCIDR(s)
	if err != nil {
		return nil, err
	}
	addr := Address(net.IPNet{IP: ip.To4(), Mask: ipNet.Mask})
	return &addr, nil
}

type PeerConfig struct {
	Name                string    `json:"name,omitempty"`
	Endpoint            string    `json:"endpoint,omitempty"`
	AllowedIPs          []Address `json:"allowedIPs,omitempty"`
	PublicKey           Key       `json:"publicKey,omitempty"`
	PersistentKeepalive int       `json:"persistentKeepalive,omitempty"`
}

func (c *PeerConfig) WriteConfig(w io.Writer) error {
	return peerTmpl.Execute(w, c)
}

func (c *PeerConfig) RenderConfig() string {
	var b strings.Builder
	err := c.WriteConfig(&b)
	if err != nil {
		panic(err)
	}
	return b.String()
}

var peerTmpl = template.Must(template.New("peer").Parse(`
[Peer]
# Name = {{.Name}}
{{- if .AllowedIPs }}
AllowedIPs = {{ range $i, $ip := .AllowedIPs -}}{{- if (gt $i 0) -}},{{- end -}}{{ $ip }}{{- end }}
{{- end }}
{{- if .Endpoint }}
Endpoint = {{.Endpoint}}
{{- end }}
PublicKey = {{.PublicKey}}
{{- if .PersistentKeepalive }}
PersistentKeepalive = {{.PersistentKeepalive}}
{{- end }}`[1:]))
