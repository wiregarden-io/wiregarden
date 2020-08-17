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
	}, &mockNetworkManager{})
	ctx := testContext()
	iface, err := a.JoinDevice(ctx, "test-device", "test-net", "")
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
			PublicKey: k.PublicKey(),
		},
		Peers:       []api.Device{},
		DeviceToken: []byte("device-token"),
	})
	lastLog, err := st.LastLogByDevice("test-device", "test-net")
	c.Assert(err, qt.IsNil)
	c.Assert(lastLog.State, qt.Equals, store.StateInterfaceJoined)
	c.Assert(lastLog.Operation, qt.Equals, store.OpJoinDevice)
	c.Assert(lastLog.Dirty, qt.Equals, true)

	err = a.ApplyInterfaceChanges(iface)
	c.Assert(err, qt.IsNil)
	lastLog, err = st.LastLogByDevice("test-device", "test-net")
	c.Assert(err, qt.IsNil)
	c.Assert(lastLog.State, qt.Equals, store.StateInterfaceUp)
	c.Assert(lastLog.Operation, qt.Equals, store.OpJoinDevice)
	c.Assert(lastLog.Dirty, qt.Equals, false)

	// Subsequent join is rejected with "already joined" error.
	_, err = a.JoinDevice(ctx, "test-device", "test-net", "")
	c.Assert(err, qt.ErrorMatches, `.*already joined.*`)
	// No change in interface state from rejected join attempt.
	lastLog2, err := st.LastLogByDevice("test-device", "test-net")
	c.Assert(err, qt.IsNil)
	c.Assert(lastLog, qt.DeepEquals, lastLog2)
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
	iface, err := a.JoinDevice(ctx, "test-device", "test-net", "")
	c.Assert(err, qt.IsNil)
	c.Assert(iface.Peers, qt.HasLen, 0)
	lastLog, err := st.LastLogByDevice("test-device", "test-net")
	c.Assert(err, qt.IsNil)

	// Cannot refresh until pending operation has been applied
	_, err = a.RefreshDevice(ctx, "test-device", "test-net", "")
	c.Assert(err, qt.ErrorMatches, `.*interface state has not been applied.*`)
	// No change in state.
	lastLog2, err := st.LastLogByDevice("test-device", "test-net")
	c.Assert(lastLog2, qt.DeepEquals, lastLog)

	// Apply pending changes, now refresh succeeds.
	err = a.ApplyInterfaceChanges(iface)
	c.Assert(err, qt.IsNil)
	iface2, err := a.RefreshDevice(ctx, "test-device", "test-net", "")
	c.Assert(err, qt.IsNil)
	c.Assert(iface.Id, qt.Equals, iface2.Id)
	c.Assert(iface.Network, qt.DeepEquals, iface2.Network)
	c.Assert(iface2.Peers, qt.HasLen, 1)

	lastLogRefresh, err := st.LastLogByDevice("test-device", "test-net")
	c.Assert(err, qt.IsNil)
	c.Assert(lastLogRefresh.Id > lastLog.Id, qt.IsTrue)
	c.Assert(lastLogRefresh.Operation, qt.Equals, store.OpRefreshDevice)
	c.Assert(lastLogRefresh.State, qt.Equals, store.StateInterfaceUp)
	c.Assert(lastLogRefresh.Dirty, qt.IsTrue)

	err = a.ApplyInterfaceChanges(iface)
	c.Assert(err, qt.IsNil)

	// Now depart device
	_, err = a.DeleteDevice(ctx, "test-device", "test-net")
	c.Assert(err, qt.IsNil)
	lastLogDelete, err := st.LastLogByDevice("test-device", "test-net")
	c.Assert(err, qt.IsNil)
	c.Assert(lastLogDelete.Id > lastLogRefresh.Id, qt.IsTrue)
	c.Assert(lastLogDelete.Operation, qt.Equals, store.OpDeleteDevice)
	c.Assert(lastLogDelete.State, qt.Equals, store.StateInterfaceDeparted)
	c.Assert(lastLogDelete.Dirty, qt.IsTrue)
	err = a.ApplyInterfaceChanges(iface)
	c.Assert(err, qt.IsNil)
	lastLogDown, err := st.LastLogByDevice("test-device", "test-net")
	c.Assert(err, qt.IsNil)
	c.Assert(lastLogDown.Id > lastLogDelete.Id, qt.IsTrue)
	c.Assert(lastLogDown.Operation, qt.Equals, store.OpDeleteDevice)
	c.Assert(lastLogDown.State, qt.Equals, store.StateInterfaceDown)
	c.Assert(lastLogDown.Dirty, qt.IsFalse)
}

func testContext() context.Context {
	return agent.WithToken(context.Background(), []byte("test-token"))
}

type mockClient struct {
	joinResponse    *api.JoinDeviceResponse
	refreshResponse *api.JoinDeviceResponse
}

func (c *mockClient) JoinDevice(context.Context, *api.JoinDeviceRequest) (*api.JoinDeviceResponse, error) {
	return c.joinResponse, nil
}

func (c *mockClient) RefreshDevice(context.Context, *api.RefreshDeviceRequest) (*api.JoinDeviceResponse, error) {
	return c.refreshResponse, nil
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
