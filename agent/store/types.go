// Copyright 2020 Cmars Technologies LLC.
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.

package store

import (
	"fmt"
	"net"
	"time"

	"github.com/wiregarden-io/wiregarden/api"
	"github.com/wiregarden-io/wiregarden/wireguard"
)

var (
	ErrInterfaceStatePending     = fmt.Errorf("interface state has not been applied")
	ErrInterfaceOperationInvalid = fmt.Errorf("operation not valid for interface state")
)

type Interface struct {
	ApiUrl      string
	Id          int64
	Network     api.Network
	Device      api.Device
	Peers       []api.Device
	Plan        api.PlanDoc
	ListenPort  int
	Key         wireguard.Key
	DeviceToken []byte
}

func (iface *Interface) Name() string {
	return fmt.Sprintf("wgn%03d", iface.Id)
}

const defaultMTUSize = 1280

func (iface *Interface) Config() *wireguard.InterfaceConfig {
	isServer := iface.Device.Endpoint != ""
	var postUp string
	if isServer {
		postUp = `sysctl -w net.ipv4.ip_forward=1`
	}
	return &wireguard.InterfaceConfig{
		Name:       iface.Name(),
		Address:    iface.Device.Addr,
		ListenPort: iface.ListenPort,
		PrivateKey: iface.Key,
		PostUp:     postUp,
		Peers:      peersModel(iface.Peers).Config(&iface.Network, iface.Device.Endpoint != ""),
		MTU:        defaultMTUSize,
	}
}

type peersModel []api.Device

func (p peersModel) Config(n *api.Network, isServer bool) []wireguard.PeerConfig {
	var result []wireguard.PeerConfig
	for i := range p {
		if isServer {
			// If the interface is configured as a server, all peers need to be
			// defined. AllowedIPs must be converted to a /32 single address,
			// as we're basically mapping public key identity to network
			// address here. Endpoint is ignored, because we're not connecting
			// out to these peers as a client. Keepalive is not set, because
			// the server can't maintain the connection with clients behind a
			// NAT.
			addr := p[i].Addr
			if p[i].Endpoint == "" {
				addr.Mask = net.CIDRMask(32, 32)
			}
			result = append(result, wireguard.PeerConfig{
				Name:       p[i].Name,
				AllowedIPs: []wireguard.Address{addr},
				PublicKey:  p[i].PublicKey,
				Endpoint:   p[i].Endpoint,
			})
		} else if p[i].Endpoint != "" {
			// If the interface is a client, then we only connect to servers.
			// AllowedIPs is used to determine routing available on the server
			// peer, so we use the peer's address CIDR.
			result = append(result, wireguard.PeerConfig{
				Name:                p[i].Name,
				Endpoint:            p[i].Endpoint,
				AllowedIPs:          []wireguard.Address{p[i].Addr},
				PublicKey:           p[i].PublicKey,
				PersistentKeepalive: 15, // TODO: configurable?
			})
		}
	}
	return result
}

// Operation represents an operation that is performed on a logical wiregarden
// device to effect a local network interface.
type Operation string

const (
	// OpJoinDevice joins a wiregarden defined network.
	OpJoinDevice = Operation("join_device")

	// OpApplyDevice applies a device definition to a local network interface.
	OpApplyDevice = Operation("apply_device")

	// OpRefreshDevice updates a device configuration if it has pending changes.
	OpRefreshDevice = Operation("refresh_device")

	// OpDeleteDevice deletes a device and its local interface.
	OpDeleteDevice = Operation("delete_device")
)

// State represents the state of a local network interface defined by
// wiregarden.
type State string

const (
	// StateInterfaceJoined means we've defined a local network interface and
	// it's linked to a wiregarden device joined to a wiregarden network.
	StateInterfaceJoined = State("interface_joined")

	// StateInterfaceUp means we've brought the defined network interface up
	// successfully.
	StateInterfaceUp = State("interface_up")

	// StateInterfaceBlocked means there was a problem with applying the last
	// operation. The Operation field in the log indicates what was attempted.
	StateInterfaceBlocked = State("interface_blocked")

	// StateInterfaceDeparted means we've departed the wiregarden network.
	StateInterfaceDeparted = State("interface_departed")

	// StateInterfaceRevoked means we've been kicked from the wiregarden network.
	StateInterfaceRevoked = State("interface_revoked")

	// StateInterfaceDown means the network interface has been brought down
	// successfully.
	StateInterfaceDown = State("interface_down")
)

type Key = [32]byte

type InterfaceLog struct {
	Id        int64
	Timestamp time.Time
	Operation Operation
	State     State
	Dirty     bool
	Message   string
}

type InterfaceWithLog struct {
	Interface
	Log InterfaceLog
}
