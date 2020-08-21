// Copyright 2020 Cmars Technologies LLC.
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.

package agent

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"os"
	"path/filepath"

	"github.com/pkg/errors"

	"github.com/wiregarden-io/wiregarden/agent/store"
	"github.com/wiregarden-io/wiregarden/api"
	"github.com/wiregarden-io/wiregarden/network"
	wg "github.com/wiregarden-io/wiregarden/wireguard"
)

var (
	ErrAlreadyJoinedDevice    = errors.New("device already joined to network")
	ErrInterfaceStateChanging = errors.New("interface state changed during operation")
	ErrInterfaceStateInvalid  = errors.New("invalid interface state")
)

type Agent struct {
	dataDir string
	apiUrl  string

	st  *store.Store
	api Client
	nm  NetworkManager
}

type Params struct {
	DataDir   string
	ApiUrl    string
	StorePath string
	StoreKey  store.Key
}

type Client interface {
	JoinDevice(context.Context, *api.JoinDeviceRequest) (*api.JoinDeviceResponse, error)
	RefreshDevice(context.Context, *api.RefreshDeviceRequest) (*api.JoinDeviceResponse, error)
	DepartDevice(ctx context.Context) error
}

type NetworkManager interface {
	EnsureInterface(iface *store.Interface) error
	RemoveInterface(iface *store.Interface) error
}

func New(dataDir, apiUrl string) (*Agent, error) {
	p, err := defaultParams(dataDir, apiUrl)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	if err != nil {
		return nil, errors.WithStack(err)
	}
	st, err := store.New(p.StorePath, p.StoreKey)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	a := &Agent{
		dataDir: p.DataDir,
		apiUrl:  p.ApiUrl,
		api:     api.New(p.ApiUrl),
		st:      st,
		nm:      &wireguardManager{dataDir: p.DataDir},
	}
	return a, nil
}

const defaultDataDir = "/var/lib/wiregarden"

func defaultParams(dataDir, apiUrl string) (Params, error) {
	if dataDir == "" {
		dataDir = defaultDataDir
	}
	err := checkDataDir(dataDir)
	if err != nil {
		return Params{}, errors.WithStack(err)
	}
	storePath := filepath.Join(dataDir, "db")
	var storeKey store.Key
	if storeKeyEnv := os.Getenv("WIREGARDEN_STORE_KEY"); storeKeyEnv != "" {
		buf, err := base64.StdEncoding.DecodeString(storeKeyEnv)
		if err != nil {
			return Params{}, errors.Wrap(err, "invalid store key")
		}
		if len(buf) != len(storeKey) {
			return Params{}, errors.New("invalid store key")
		}
		copy(storeKey[:], buf[:])
	} else {
		storeKey, err = ensureStoreKey(filepath.Join(dataDir, "db.key"))
		if err != nil {
			return Params{}, errors.WithStack(err)
		}
	}
	return Params{
		DataDir:   dataDir,
		ApiUrl:    apiUrl,
		StorePath: storePath,
		StoreKey:  storeKey,
	}, nil
}

func checkDataDir(dataDir string) error {
	err := os.MkdirAll(dataDir, 0700)
	if err != nil {
		return errors.Wrapf(err, "failed to create data directory %q", dataDir)
	}
	check := dataDir + "/.check"
	f, err := os.Create(check)
	if err != nil {
		return errors.Wrapf(err, "cannot write to data directory %q", dataDir)
	}
	defer f.Close()
	defer os.Remove(check)
	return nil
}

func ensureStoreKey(keyPath string) (store.Key, error) {
	var key store.Key
	f, err := os.Open(keyPath)
	if err != nil {
		if os.IsNotExist(err) {
			return generateStoreKey(keyPath)
		}
		return store.Key{}, errors.Wrapf(err, "failed to open store key %q", keyPath)
	}
	defer f.Close()
	if n, err := f.Read(key[:]); err != nil {
		return store.Key{}, errors.Wrapf(err, "failed to read store key %q", keyPath)
	} else if n != len(key) {
		return store.Key{}, errors.Errorf("invalid store key %q", keyPath)
	}
	return key, nil
}

func generateStoreKey(keyPath string) (store.Key, error) {
	f, err := os.Create(keyPath)
	if err != nil {
		return store.Key{}, errors.Wrapf(err, "failed to create store key %q", keyPath)
	}
	defer f.Close()
	var k store.Key
	_, err = rand.Reader.Read(k[:])
	if err != nil {
		return store.Key{}, errors.Wrapf(err, "failed to generate new store key %q", keyPath)
	}
	_, err = f.Write(k[:])
	if err != nil {
		return store.Key{}, errors.Wrapf(err, "failed to write new store key %q", keyPath)
	}
	return k, nil
}

func (a *Agent) JoinDevice(ctx context.Context, deviceName, networkName, endpoint string) (*store.Interface, error) {
	var err error
	if deviceName == "" {
		deviceName, err = os.Hostname()
		if err != nil {
			return nil, errors.Wrap(err, "cannot determine hostname, node name is required")
		}
	}

	if networkName == "" {
		networkName = "default"
	}

	_, err = a.st.LastLogByDevice(deviceName, networkName)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return nil, errors.Wrapf(err, "failed to query last log by device %q network %q", deviceName, networkName)
		}
	} else {
		return nil, errors.WithStack(ErrAlreadyJoinedDevice)
	}

	machineId, err := MachineId()
	if err != nil {
		return nil, errors.Wrap(err, "cannot determine machine ID")
	}

	key, err := wg.GenerateKey()
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate key")
	}

	// TODO: only really need to do this if we're starting a new network.
	availNet, err := network.RandomSubnetV4()
	if err != nil {
		return nil, errors.Wrap(err, "failed to find an available subnet")
	}
	availAddr, err := wg.ParseAddress(availNet)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse network %q", availNet)
	}

	listenPort, err := findListenPort(endpoint)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to find an available listen port")
	}

	joinResp, err := a.api.JoinDevice(ctx, &api.JoinDeviceRequest{
		Name:          deviceName,
		Network:       networkName,
		MachineId:     machineId,
		Key:           key.PublicKey(),
		Endpoint:      endpoint,
		AvailableAddr: *availAddr,
		AvailablePort: listenPort,
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to join device to network")
	}

	var iface store.Interface
	iface.ListenPort = listenPort
	iface.Key = key
	a.ifaceJoinDeviceResponse(&iface, joinResp)
	err = a.st.WithLog(&iface, func(tx *sql.Tx, lastLog *store.InterfaceLog) error {
		if lastLog != nil {
			return errors.Wrapf(ErrInterfaceStateChanging,
				"expected no prior state, found %q at entry %d", lastLog.State, lastLog.Id)
		}
		err := a.st.EnsureInterfaceTx(tx, &iface)
		if err != nil {
			return errors.Wrap(err, "failed to store interface")
		}
		err = store.AppendLogTx(tx, &iface, store.OpJoinDevice, store.StateInterfaceJoined, true, "")
		if err != nil {
			return errors.WithStack(err)
		}
		return nil
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return &iface, nil
}

func (a *Agent) ifaceJoinDeviceResponse(iface *store.Interface, joinResp *api.JoinDeviceResponse) {
	iface.ApiUrl = a.apiUrl
	iface.Network = joinResp.Network
	iface.Device = joinResp.Device
	iface.Peers = joinResp.Peers
	iface.Plan = joinResp.Plan
	if joinResp.Token != nil {
		iface.DeviceToken = joinResp.Token
	}
}

func (a *Agent) RefreshDevice(ctx context.Context, deviceName, networkName, endpoint string) (*store.Interface, error) {
	var err error
	if deviceName == "" {
		deviceName, err = os.Hostname()
		if err != nil {
			return nil, errors.Wrap(err, "cannot determine hostname, node name is required")
		}
	}

	if networkName == "" {
		networkName = "default"
	}

	iface, err := a.st.InterfaceByDevice(deviceName, networkName)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	lastLog, err := a.st.LastLogByDevice(deviceName, networkName)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	// If there is an unapplied operation pending, let's try to apply it now.
	if lastLog.Dirty {
		err = a.ApplyInterfaceChanges(iface)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		lastLog, err = a.st.LastLogByDevice(deviceName, networkName)
		if err != nil {
			return nil, errors.WithStack(err)
		}
	}
	err = a.allowOperation(lastLog, store.OpRefreshDevice)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	joinResp, err := a.api.RefreshDevice(WithToken(ctx, iface.DeviceToken), &api.RefreshDeviceRequest{
		Endpoint: endpoint,
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}
	a.ifaceJoinDeviceResponse(iface, joinResp)
	err = a.st.WithLog(iface, func(tx *sql.Tx, currentLastLog *store.InterfaceLog) error {
		if *lastLog != *currentLastLog {
			return errors.Wrapf(ErrInterfaceStateChanging,
				"interface state has changed, was %q at entry %d, found %q at entry %d",
				lastLog.State, lastLog.Id, currentLastLog.State, currentLastLog.Id)
		}
		err := a.st.EnsureInterfaceTx(tx, iface)
		if err != nil {
			return errors.Wrap(err, "failed to store interface")
		}
		err = store.AppendLogTx(tx, iface, store.OpRefreshDevice, store.StateInterfaceUp, true, "")
		if err != nil {
			return errors.WithStack(err)
		}
		return nil
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return iface, nil
}

func (a *Agent) allowOperation(l *store.InterfaceLog, op store.Operation) error {
	if l != nil && l.Dirty {
		return errors.WithStack(store.ErrInterfaceStatePending)
	}
	switch op {
	case store.OpJoinDevice:
		// Join is only valid if there is no prior state. If join fails, we never commit that state.
		if l == nil {
			return nil
		}
	case store.OpRefreshDevice:
		if l.State == store.StateInterfaceUp {
			return nil
		}
		// Allow retrying refresh, but not if other operations have been attempted like delete
		if l.State == store.StateInterfaceBlocked && l.Operation == op {
			return nil
		}
	case store.OpDeleteDevice:
		if l.State == store.StateInterfaceUp {
			return nil
		}
		// Allow deleting the device even if currently retrying some other operation like refresh
		if l.State == store.StateInterfaceBlocked {
			return nil
		}
	}
	// TODO: we'll need to clean these up most likely
	return errors.WithStack(store.ErrInterfaceOperationInvalid)
}

func (a *Agent) DeleteDevice(ctx context.Context, deviceName, networkName string) (*store.Interface, error) {
	var err error
	if deviceName == "" {
		deviceName, err = os.Hostname()
		if err != nil {
			return nil, errors.Wrap(err, "cannot determine hostname, node name is required")
		}
	}

	if networkName == "" {
		networkName = "default"
	}

	iface, err := a.st.InterfaceByDevice(deviceName, networkName)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	lastLog, err := a.st.LastLogByDevice(deviceName, networkName)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	err = a.allowOperation(lastLog, store.OpDeleteDevice)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	err = a.api.DepartDevice(WithToken(ctx, iface.DeviceToken))
	if err != nil {
		return nil, errors.Wrap(err, "failed to depart network")
	}
	err = a.st.WithLog(iface, func(tx *sql.Tx, currentLastLog *store.InterfaceLog) error {
		if *lastLog != *currentLastLog {
			return errors.Wrapf(ErrInterfaceStateChanging,
				"interface state has changed, was %q at entry %d, found %q at entry %d",
				lastLog.State, lastLog.Id, currentLastLog.State, currentLastLog.Id)
		}
		err = store.AppendLogTx(tx, iface, store.OpDeleteDevice, store.StateInterfaceDeparted, true, "")
		if err != nil {
			return errors.WithStack(err)
		}
		return nil
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return iface, nil
}

func (a *Agent) Interfaces() ([]store.InterfaceWithLog, error) {
	ifaces, err := a.st.Interfaces()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return ifaces, nil
}

func (a *Agent) ApplyInterfaceChanges(iface *store.Interface) error {
	err := a.st.WithLog(iface, func(tx *sql.Tx, lastLog *store.InterfaceLog) error {
		if !lastLog.Dirty {
			return nil
		}
		nextLog, err := a.applyInterfaceChanges(iface, lastLog)
		if err != nil {
			nextLog = &store.InterfaceLog{
				Operation: lastLog.Operation,
				State:     store.StateInterfaceBlocked,
				Dirty:     true,
				Message:   err.Error(),
			}
		}
		err = store.AppendLogTx(tx, iface, nextLog.Operation, nextLog.State, nextLog.Dirty, nextLog.Message)
		return errors.WithStack(err)
	})
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func (a *Agent) applyInterfaceChanges(iface *store.Interface, lastLog *store.InterfaceLog) (*store.InterfaceLog, error) {
	switch lastLog.State {
	case store.StateInterfaceJoined, store.StateInterfaceUp:
		return &store.InterfaceLog{
			Operation: lastLog.Operation,
			State:     store.StateInterfaceUp,
		}, a.nm.EnsureInterface(iface)
	case store.StateInterfaceDeparted:
		return &store.InterfaceLog{
			Operation: lastLog.Operation,
			State:     store.StateInterfaceDown,
		}, a.nm.RemoveInterface(iface)
	case store.StateInterfaceBlocked:
		switch lastLog.Operation {
		case store.OpJoinDevice, store.OpRefreshDevice:
			return &store.InterfaceLog{
				Operation: lastLog.Operation,
				State:     store.StateInterfaceUp,
			}, a.nm.EnsureInterface(iface)
		case store.OpDeleteDevice:
			return &store.InterfaceLog{
				Operation: lastLog.Operation,
				State:     store.StateInterfaceDown,
			}, a.nm.RemoveInterface(iface)
		}
	}
	return nil, errors.Wrapf(ErrInterfaceStateInvalid, "don't know how to apply changes for state %q operation %q", lastLog.State, lastLog.Operation)
}

func WithToken(ctx context.Context, token []byte) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, "token", token)
}
