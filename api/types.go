// Copyright 2020 Cmars Technologies LLC.
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.

package api

import (
	"net"
	"time"

	"github.com/pkg/errors"

	"github.com/wiregarden-io/wiregarden/wireguard"
)

type ListSubscriptionsResponse struct {
	Subscriptions []GetSubscriptionResponse `json:"subscriptions"`
}

type GetSubscriptionResponse struct {
	Id        string      `json:"id"`
	Created   time.Time   `json:"created"`
	NotBefore *time.Time  `json:"notBefore"`
	NotAfter  *time.Time  `json:"notAfter"`
	Plan      PlanDoc     `json:"plan"`
	Tokens    []TokenInfo `json:"tokens"`
}

type TokenInfo struct {
	Token     []byte     `json:"token"`
	Created   time.Time  `json:"created"`
	NotBefore *time.Time `json:"notBefore"`
	NotAfter  *time.Time `json:"notAfter"`
}

type PlanDoc struct {
	Name                    string `json:"name"`
	Free                    bool   `json:"free"`
	DeviceLimit             int    `json:"deviceLimit,omitempty"`
	ExpiresInDays           int    `json:"expiresInDays,omitempty"`
	MaxDeviceUpdatesPerHour int    `json:"maxDeviceRefreshesPerHour,omitempty"`
}

type GetSubscriptionTokenResponse struct {
	Id    string `json:"id"`
	Token []byte `json:"token"`
}

type JoinDeviceRequest struct {
	// A logical name given to the device on join.
	Name string `json:"name"`
	// Network to join. Default network for this subscription if empty.
	Network string `json:"network,omitempty"`
	// App-specific machine ID, protecting actual machine ID.
	MachineId []byte `json:"machineId"`
	// Public key of this device.
	Key wireguard.Key `json:"key"`
	// Public endpoint where this device can be reached, if possible.
	Endpoint string `json:"endpoint,omitempty"`
	// Available address on this device. Used if starting a new network.
	AvailableAddr wireguard.Address `json:"availableAddr,omitempty"`
	// Available port on this device.
	AvailablePort int `json:"availablePort,omitempty"`
	// Request a specific static address for this device.
	StaticAddr *wireguard.Address `json:"staticAddr,omitempty"`
}

func (r *JoinDeviceRequest) Valid() error {
	if len(r.MachineId) != 32 {
		return errors.Errorf("invalid machine ID length %d", len(r.MachineId))
	}
	if len(r.Key) != 32 {
		return errors.Errorf("invalid key length %d", len(r.Key))
	}
	if r.AvailablePort < 0 || r.AvailablePort > 65535 {
		return errors.Errorf("invalid port %d", r.AvailablePort)
	}
	return nil
}

type JoinDeviceResponse struct {
	Network Network `json:"network"`
	// Assigned device, which persists for the lifetime of this device's
	// membership in the network.
	Device Device `json:"device"`
	// Peers available to this device on this network.
	Peers []Device `json:"peers"`
	// Plan information about subscription
	Plan PlanDoc `json:"plan"`
	// Device token, stored and used for making subsequent device requests
	Token []byte `json:"token"`
}

type ListDevicesResponse struct {
	Devices []GetDeviceResponse `json:"devices"`
}

type GetDeviceResponse struct {
	Network Network `json:"network"`
	Device  Device  `json:"device"`
}

type Device struct {
	Id        string            `json:"id"`
	Name      string            `json:"name"`
	Endpoint  string            `json:"endpoint"`
	Addr      wireguard.Address `json:"addr"`
	PublicKey wireguard.Key     `json:"publicKey"`
}

type Network struct {
	Id   string            `json:"id"`
	Name string            `json:"name"`
	CIDR wireguard.Address `json:"address"`
}

type RefreshDeviceRequest struct {
	// Assigned logical device name
	Name string `json:"name,omitempty"`
	// Public key of this device.
	Key wireguard.Key `json:"key,omitempty"`
	// Public endpoint where this device can be reached, if possible.
	Endpoint string `json:"endpoint,omitempty"`
}

func (r *RefreshDeviceRequest) Valid() error {
	if len(r.Key) > 0 && len(r.Key) != 32 {
		return errors.Errorf("invalid key length %d", len(r.Key))
	}
	if len(r.Endpoint) > 0 {
		_, _, err := net.SplitHostPort(r.Endpoint)
		if err != nil {
			return errors.Wrapf(err, "invalid endpoint")
		}
	}
	return nil
}
