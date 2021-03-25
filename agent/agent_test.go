// Copyright 2020 Cmars Technologies LLC.
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.

package agent_test

import (
	"context"
	"testing"

	qt "github.com/frankban/quicktest"

	"github.com/wiregarden-io/wiregarden/agent"
	"github.com/wiregarden-io/wiregarden/agent/store"
	"github.com/wiregarden-io/wiregarden/api"
	"github.com/wiregarden-io/wiregarden/wireguard"
)

func TestJoinApply(t *testing.T) {
	c := qt.New(t)
	a, st := agent.NewTestAgent(c, &mockClient{
		joinResponse: &api.JoinDeviceResponse{
			Network: api.Network{
				Id:   "test-net-id",
				Name: "test-net",
				CIDR: parseAddress(c, "1.2.3.0/24"),
			},
			Device: api.Device{
				Id:   "test-device-id",
				Name: "test-device",
				Addr: parseAddress(c, "1.2.3.4/24"),
				// throwaway key that we'll ignore when comparing expected interface below
				PublicKey: generateKey(c).PublicKey(),
			},
			Peers: []api.Device{},
			Token: []byte("device-token"),
		},
	}, &mockNetworkManager{})
	ctx := testContext()
	iface, err := a.JoinDevice(ctx, agent.JoinArgs{Name: "test-device", Network: "test-net"})
	c.Assert(err, qt.IsNil)
	c.Assert(iface, qt.DeepEquals, &store.Interface{
		ApiUrl: "https://wiregarden.io/api",
		Id:     1,
		Network: api.Network{
			Id:   "test-net-id",
			Name: "test-net",
			CIDR: parseAddress(c, "1.2.3.0/24"),
		},
		Device: api.Device{
			Id:        "test-device-id",
			Name:      "test-device",
			Addr:      parseAddress(c, "1.2.3.4/24"),
			PublicKey: iface.Device.PublicKey, // not tested
		},
		Peers:       []api.Device{},
		ListenPort:  iface.ListenPort, // not tested
		Key:         iface.Key,        // not tested
		DeviceToken: []byte("device-token"),
	})
	ifaceLog, err := st.LastLogByDevice("test-device", "test-net")
	c.Assert(err, qt.IsNil)
	c.Assert(ifaceLog.Log.State, qt.Equals, store.StateInterfaceJoined)
	c.Assert(ifaceLog.Log.Operation, qt.Equals, store.OpJoinDevice)
	c.Assert(ifaceLog.Log.Dirty, qt.Equals, true)

	err = a.ApplyInterfaceChanges(ctx, iface)
	c.Assert(err, qt.IsNil)
	ifaceLog, err = st.LastLogByDevice("test-device", "test-net")
	c.Assert(err, qt.IsNil)
	c.Assert(ifaceLog.Log.State, qt.Equals, store.StateInterfaceUp)
	c.Assert(ifaceLog.Log.Operation, qt.Equals, store.OpJoinDevice)
	c.Assert(ifaceLog.Log.Dirty, qt.Equals, false)

	// Subsequent join is rejected with "already joined" error.
	_, err = a.JoinDevice(ctx, agent.JoinArgs{Name: "test-device", Network: "test-net"})
	c.Assert(err, qt.ErrorMatches, `.*already joined.*`)
	// No change in interface state from rejected join attempt.
	ifaceLog2, err := st.LastLogByDevice("test-device", "test-net")
	c.Assert(err, qt.IsNil)
	c.Assert(ifaceLog, qt.DeepEquals, ifaceLog2)
}

func TestJoinRefreshDepart(t *testing.T) {
	c := qt.New(t)
	k := generateKey(c)
	a, st := agent.NewTestAgent(c, &mockClient{
		joinResponse: &api.JoinDeviceResponse{
			Network: api.Network{
				Id:   "test-net-id",
				Name: "test-net",
				CIDR: parseAddress(c, "1.2.3.0/24"),
			},
			Device: api.Device{
				Id:        "test-device-id",
				Name:      "test-device",
				Addr:      parseAddress(c, "1.2.3.4/24"),
				PublicKey: k.PublicKey(),
			},
			Peers: []api.Device{},
			Token: []byte("device-token"),
		},
		refreshResponse: &api.JoinDeviceResponse{
			Network: api.Network{
				Id:   "test-net-id",
				Name: "test-net",
				CIDR: parseAddress(c, "1.2.3.0/24"),
			},
			Device: api.Device{
				Id:        "test-device-id",
				Name:      "test-device",
				Addr:      parseAddress(c, "1.2.3.4/24"),
				PublicKey: k.PublicKey(),
			},
			Peers: []api.Device{{
				Id:        "test-device-2-id",
				Name:      "test-device-2",
				Addr:      parseAddress(c, "1.2.3.5/24"),
				PublicKey: generateKey(c).PublicKey(),
			}},
			Token: []byte("device-token"),
		},
	}, &mockNetworkManager{})
	ctx := testContext()
	iface, err := a.JoinDevice(ctx, agent.JoinArgs{Name: "test-device", Network: "test-net"})
	c.Assert(err, qt.IsNil)
	c.Assert(iface.Peers, qt.HasLen, 0)
	ifaceLog, err := st.LastLogByDevice("test-device", "test-net")
	c.Assert(err, qt.IsNil)

	// Refresh will apply pending operations
	iface2, err := a.RefreshDevice(ctx, agent.JoinArgs{Name: "test-device", Network: "test-net"})
	c.Assert(err, qt.IsNil)
	c.Assert(iface.Id, qt.Equals, iface2.Id)
	c.Assert(iface.Network, qt.DeepEquals, iface2.Network)
	c.Assert(iface2.Peers, qt.HasLen, 1)

	ifaceLogRefresh, err := st.LastLogByDevice("test-device", "test-net")
	c.Assert(err, qt.IsNil)
	c.Assert(ifaceLogRefresh.Log.Id > ifaceLog.Log.Id, qt.IsTrue)
	c.Assert(ifaceLogRefresh.Log.Operation, qt.Equals, store.OpRefreshDevice)
	c.Assert(ifaceLogRefresh.Log.State, qt.Equals, store.StateInterfaceUp)
	c.Assert(ifaceLogRefresh.Log.Dirty, qt.IsTrue)

	err = a.ApplyInterfaceChanges(ctx, &ifaceLogRefresh.Interface)
	c.Assert(err, qt.IsNil)

	// Now depart device
	_, err = a.DeleteDevice(ctx, "test-device", "test-net")
	c.Assert(err, qt.IsNil)
	ifaceLogDelete, err := st.LastLogByDevice("test-device", "test-net")
	c.Assert(err, qt.IsNil)
	c.Assert(ifaceLogDelete.Log.Id > ifaceLogRefresh.Log.Id, qt.IsTrue)
	c.Assert(ifaceLogDelete.Log.Operation, qt.Equals, store.OpDeleteDevice)
	c.Assert(ifaceLogDelete.Log.State, qt.Equals, store.StateInterfaceDeparted)
	c.Assert(ifaceLogDelete.Log.Dirty, qt.IsTrue)
	err = a.ApplyInterfaceChanges(ctx, iface)
	c.Assert(err, qt.IsNil)
	lastLogDown, err := st.LastLogByDevice("test-device", "test-net")
	c.Assert(err, qt.IsNil)
	c.Assert(lastLogDown.Log.Id > ifaceLogDelete.Log.Id, qt.IsTrue)
	c.Assert(lastLogDown.Log.Operation, qt.Equals, store.OpDeleteDevice)
	c.Assert(lastLogDown.Log.State, qt.Equals, store.StateInterfaceDown)
	c.Assert(lastLogDown.Log.Dirty, qt.IsFalse)
}

func TestJoinRefreshRevoked(t *testing.T) {
	c := qt.New(t)
	k := generateKey(c)
	a, st := agent.NewTestAgent(c, &mockClient{
		joinResponse: &api.JoinDeviceResponse{
			Network: api.Network{
				Id:   "test-net-id",
				Name: "test-net",
				CIDR: parseAddress(c, "1.2.3.0/24"),
			},
			Device: api.Device{
				Id:        "test-device-id",
				Name:      "test-device",
				Addr:      parseAddress(c, "1.2.3.4/24"),
				PublicKey: k.PublicKey(),
			},
			Peers: []api.Device{},
			Token: []byte("device-token"),
		},
		refreshErr: api.ErrApiRevoked,
	}, &mockNetworkManager{})
	ctx := testContext()
	iface, err := a.JoinDevice(ctx, agent.JoinArgs{Name: "test-device", Network: "test-net"})
	c.Assert(err, qt.IsNil)
	c.Assert(iface.Peers, qt.HasLen, 0)
	ifaceLog, err := st.LastLogByDevice("test-device", "test-net")
	c.Assert(err, qt.IsNil)

	// Refresh discovers we've been kicked
	iface2, err := a.RefreshDevice(ctx, agent.JoinArgs{Name: "test-device", Network: "test-net"})
	c.Assert(err, qt.IsNil)
	c.Assert(iface.Id, qt.Equals, iface2.Id)
	c.Assert(iface.Network, qt.DeepEquals, iface2.Network)
	c.Assert(iface2.Peers, qt.HasLen, 0)

	ifaceLogRefresh, err := st.LastLogByDevice("test-device", "test-net")
	c.Assert(err, qt.IsNil)
	c.Assert(ifaceLogRefresh.Log.Id > ifaceLog.Log.Id, qt.IsTrue)
	c.Assert(ifaceLogRefresh.Log.Operation, qt.Equals, store.OpRefreshDevice)
	c.Assert(ifaceLogRefresh.Log.State, qt.Equals, store.StateInterfaceRevoked)
	c.Assert(ifaceLogRefresh.Log.Dirty, qt.IsTrue)

	err = a.ApplyInterfaceChanges(ctx, &ifaceLogRefresh.Interface)
	c.Assert(err, qt.IsNil)

	lastLog, err := st.LastLog(iface)
	c.Assert(err, qt.IsNil)
	c.Assert(lastLog.Id > ifaceLog.Log.Id, qt.IsTrue)
	c.Assert(lastLog.Operation, qt.Equals, store.OpRefreshDevice)
	c.Assert(lastLog.State, qt.Equals, store.StateInterfaceDown)
	c.Assert(lastLog.Dirty, qt.IsFalse)
}

func TestRefreshEndpoint(t *testing.T) {
	c := qt.New(t)
	k := generateKey(c)
	a, st := agent.NewTestAgent(c, &mockClient{
		c: c,
		joinResponse: &api.JoinDeviceResponse{
			Network: api.Network{
				Id:   "test-net-id",
				Name: "test-net",
				CIDR: parseAddress(c, "1.2.3.0/24"),
			},
			Device: api.Device{
				Id:        "test-device-id",
				Name:      "test-device",
				Addr:      parseAddress(c, "1.2.3.4/24"),
				PublicKey: k.PublicKey(),
			},
			Peers: []api.Device{},
			Token: []byte("device-token"),
		},
		expectRefreshRequest: &api.RefreshDeviceRequest{
			Endpoint: "10.20.30.40:50607",
		},
		refreshResponse: &api.JoinDeviceResponse{
			Network: api.Network{
				Id:   "test-net-id",
				Name: "test-net",
				CIDR: parseAddress(c, "1.2.3.0/24"),
			},
			Device: api.Device{
				Id:        "test-device-id",
				Name:      "test-device",
				Addr:      parseAddress(c, "1.2.3.4/24"),
				PublicKey: k.PublicKey(),
				Endpoint:  "10.20.30.40:50607",
			},
			Peers: []api.Device{{
				Id:        "test-device-2-id",
				Name:      "test-device-2",
				Addr:      parseAddress(c, "1.2.3.5/24"),
				PublicKey: generateKey(c).PublicKey(),
			}},
			Token: []byte("device-token"),
		},
	}, &mockNetworkManager{})
	ctx := testContext()
	iface, err := a.JoinDevice(ctx, agent.JoinArgs{Name: "test-device", Network: "test-net"})
	c.Assert(err, qt.IsNil)
	c.Assert(iface.Peers, qt.HasLen, 0)
	c.Assert(iface.Device.Endpoint, qt.Equals, "")
	_, err = st.LastLogByDevice("test-device", "test-net")
	c.Assert(err, qt.IsNil)

	// Refresh with new endpoint
	_, err = a.RefreshDevice(ctx, agent.JoinArgs{Name: "test-device", Network: "test-net", Endpoint: "10.20.30.40:50607"})
	c.Assert(err, qt.IsNil)
}

func testContext() context.Context {
	return agent.WithToken(context.Background(), []byte("test-token"))
}

type mockClient struct {
	c                    *qt.C
	joinResponse         *api.JoinDeviceResponse
	expectRefreshRequest *api.RefreshDeviceRequest
	refreshResponse      *api.JoinDeviceResponse
	refreshErr           error
}

func (c *mockClient) JoinDevice(context.Context, *api.JoinDeviceRequest) (*api.JoinDeviceResponse, error) {
	return c.joinResponse, nil
}

func (c *mockClient) RefreshDevice(_ context.Context, req *api.RefreshDeviceRequest) (*api.JoinDeviceResponse, error) {
	if c.expectRefreshRequest != nil {
		c.c.Assert(req, qt.DeepEquals, c.expectRefreshRequest)
	}
	return c.refreshResponse, c.refreshErr
}

func (c *mockClient) DepartDevice(ctx context.Context) error {
	return nil
}

type mockNetworkManager struct {
}

func (m *mockNetworkManager) EnsureInterface(iface *store.Interface) error {
	return nil
}

func (m *mockNetworkManager) RemoveInterface(iface *store.Interface) error {
	return nil
}

func parseAddress(c *qt.C, addr string) wireguard.Address {
	a, err := wireguard.ParseAddress(addr)
	c.Assert(err, qt.IsNil)
	return *a
}

func generateKey(c *qt.C) wireguard.Key {
	k, err := wireguard.GenerateKey()
	c.Assert(err, qt.IsNil)
	return k
}
