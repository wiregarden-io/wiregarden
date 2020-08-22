// Copyright 2020 Cmars Technologies LLC.
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.

package store_test

import (
	"crypto/rand"
	"database/sql"
	"testing"

	qt "github.com/frankban/quicktest"
	"github.com/pkg/errors"

	"github.com/wiregarden-io/wiregarden/agent/store"
	"github.com/wiregarden-io/wiregarden/api"
	"github.com/wiregarden-io/wiregarden/wireguard"
)

func TestNewStore(t *testing.T) {
	c := qt.New(t)
	_, err := store.New(":memory:", generateStoreKey(c))
	c.Assert(err, qt.IsNil)
}

func generateStoreKey(c *qt.C) store.Key {
	var k store.Key
	_, err := rand.Reader.Read(k[:])
	c.Assert(err, qt.IsNil)
	return k
}

func TestInterfaceNoPeers(t *testing.T) {
	c := qt.New(t)
	st, err := store.New(":memory:", generateStoreKey(c))
	c.Assert(err, qt.IsNil)
	defer st.Close()
	k := generateKey(c)
	iface := &store.Interface{
		ApiUrl: "https://wiregarden.io/api",
		Network: api.Network{
			Id:   "test-net-id",
			Name: "test-net",
			CIDR: parseAddress(c, "1.2.3.0/24"),
		},
		Device: api.Device{
			Id:        "test-device-id",
			Name:      "test-device",
			Endpoint:  "example.com",
			Addr:      parseAddress(c, "1.2.3.4/24"),
			PublicKey: k.PublicKey(),
		},
		ListenPort:  12345,
		Key:         k,
		DeviceToken: []byte("itsasecrettoeverybody"),
	}
	err = st.EnsureInterface(iface)
	c.Assert(err, qt.IsNil)
	c.Assert(iface.Name(), qt.Equals, "wgn001")
	err = st.EnsureInterface(iface)
	c.Assert(err, qt.IsNil)

	iface2, err := st.Interface(1)
	c.Assert(err, qt.IsNil)

	c.Assert(iface, qt.DeepEquals, iface2)
}

func TestInterfacePeers(t *testing.T) {
	c := qt.New(t)
	st, err := store.New(":memory:", generateStoreKey(c))
	c.Assert(err, qt.IsNil)
	defer st.Close()
	k := generateKey(c)
	iface := &store.Interface{
		ApiUrl: "https://wiregarden.io/api",
		Network: api.Network{
			Id:   "test-net-id",
			Name: "test-net",
			CIDR: parseAddress(c, "1.2.3.0/24"),
		},
		Device: api.Device{
			Id:        "test-device-id",
			Name:      "test-device",
			Endpoint:  "example.com",
			Addr:      parseAddress(c, "1.2.3.4/24"),
			PublicKey: k.PublicKey(),
		},
		Peers: []api.Device{{
			Id:        "test-peer-1-id",
			Name:      "test-peer-1",
			Addr:      parseAddress(c, "1.2.3.5/24"),
			PublicKey: generateKey(c).PublicKey(),
		}, {
			Id:        "test-peer-2-id",
			Name:      "test-peer-2",
			Addr:      parseAddress(c, "1.2.3.6/24"),
			PublicKey: generateKey(c).PublicKey(),
		}},
		ListenPort:  12345,
		Key:         k,
		DeviceToken: []byte("itsasecrettoeverybody"),
	}
	err = st.EnsureInterface(iface)
	c.Assert(err, qt.IsNil)
	err = st.EnsureInterface(iface)
	c.Assert(err, qt.IsNil)

	iface2, err := st.Interface(1)
	c.Assert(err, qt.IsNil)

	// Otherwise same contents
	c.Assert(iface, qt.DeepEquals, iface2)

	iface3, err := st.InterfaceByDevice("test-device", "test-net")
	c.Assert(err, qt.IsNil)
	c.Assert(iface, qt.DeepEquals, iface3)

	// No last log
	err = st.WithLog(iface, func(tx *sql.Tx, lastLog *store.InterfaceLog) error {
		c.Assert(lastLog, qt.IsNil)
		return nil
	})
	c.Assert(err, qt.IsNil)

	_, err = st.LastLogByDevice("test-device", "test-net")
	c.Assert(errors.Is(err, sql.ErrNoRows), qt.IsTrue)
}

func TestInterfaceLog(t *testing.T) {
	c := qt.New(t)
	st, err := store.New(":memory:", generateStoreKey(c))
	c.Assert(err, qt.IsNil)
	defer st.Close()
	k := generateKey(c)
	iface := &store.Interface{
		ApiUrl: "https://wiregarden.io/api",
		Network: api.Network{
			Id:   "test-net-id",
			Name: "test-net",
			CIDR: parseAddress(c, "1.2.3.0/24"),
		},
		Device: api.Device{
			Id:        "test-device-id",
			Name:      "test-device",
			Endpoint:  "example.com",
			Addr:      parseAddress(c, "1.2.3.4/24"),
			PublicKey: k.PublicKey(),
		},
		Peers: []api.Device{{
			Id:        "test-peer-1-id",
			Name:      "test-peer-1",
			Addr:      parseAddress(c, "1.2.3.5/24"),
			PublicKey: generateKey(c).PublicKey(),
		}},
	}
	err = st.EnsureInterface(iface)
	c.Assert(err, qt.IsNil)
	err = st.WithLog(iface, func(tx *sql.Tx, lastLog *store.InterfaceLog) error {
		c.Assert(lastLog, qt.IsNil)
		err := store.AppendLogTx(tx, iface, store.OpJoinDevice, store.StateInterfaceJoined, true, "hello")
		c.Assert(err, qt.IsNil)
		return nil
	})
	c.Assert(err, qt.IsNil)
	err = st.WithLog(iface, func(tx *sql.Tx, lastLog *store.InterfaceLog) error {
		ts := lastLog.Timestamp
		c.Assert(lastLog, qt.DeepEquals, &store.InterfaceLog{
			Id:        1,
			Timestamp: ts,
			Operation: "join_device",
			State:     "interface_joined",
			Dirty:     true,
			Message:   "hello",
		})
		err := store.AppendLogTx(tx, iface, store.OpJoinDevice, store.StateInterfaceUp, false, "")
		c.Assert(err, qt.IsNil)
		return nil
	})
	c.Assert(err, qt.IsNil)
	ifaceLog, err := st.LastLogByDevice("test-device", "test-net")
	c.Assert(err, qt.IsNil)
	c.Assert(ifaceLog.Log, qt.DeepEquals, store.InterfaceLog{
		Id:        2,
		Timestamp: ifaceLog.Log.Timestamp,
		Operation: "join_device",
		State:     "interface_up",
		Dirty:     false,
	})
}

func TestInterfaceUpsertUniqueConflict(t *testing.T) {
	c := qt.New(t)
	st, err := store.New(":memory:", generateStoreKey(c))
	c.Assert(err, qt.IsNil)
	defer st.Close()
	k := generateKey(c)
	iface := store.Interface{
		ApiUrl: "https://wiregarden.io/api",
		Network: api.Network{
			Id:   "test-net-id",
			Name: "test-net",
			CIDR: parseAddress(c, "1.2.3.0/24"),
		},
		Device: api.Device{
			Id:        "test-device-id",
			Name:      "test-device",
			Endpoint:  "example.com",
			Addr:      parseAddress(c, "1.2.3.4/24"),
			PublicKey: k.PublicKey(),
		},
		ListenPort:  12345,
		Key:         k,
		DeviceToken: []byte("itsasecrettoeverybody"),
	}
	iface2 := iface
	err = st.EnsureInterface(&iface)
	c.Assert(err, qt.IsNil)
	c.Assert(iface.Name(), qt.Equals, "wgn001")
	err = st.EnsureInterface(&iface)
	c.Assert(err, qt.IsNil)

	ifaceQuery, err := st.Interface(1)
	c.Assert(err, qt.IsNil)
	c.Assert(&iface, qt.DeepEquals, ifaceQuery)

	err = st.EnsureInterface(&iface2)
	c.Assert(err, qt.IsNil)
	c.Assert(iface2.Name(), qt.Equals, "wgn001")
	err = st.EnsureInterface(&iface2)
	c.Assert(err, qt.IsNil)

	c.Assert(iface, qt.DeepEquals, iface2)
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
