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
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gosuri/uitable"
	"github.com/juju/zaputil/zapctx"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh/terminal"

	"github.com/wiregarden-io/wiregarden/client"
	"github.com/wiregarden-io/wiregarden/network"
	"github.com/wiregarden-io/wiregarden/types"
)

var (
	defaultDataDir = "/var/lib/wiregarden"
)

func init() {
	if snapCommon := os.Getenv("SNAP_COMMON"); snapCommon != "" {
		defaultDataDir = snapCommon
	}
}

type App struct {
	dataDir string
	url     string
}

func New(dataDir, url string) *App {
	if dataDir == "" {
		dataDir = defaultDataDir
	}
	return &App{
		dataDir: dataDir,
		url:     url,
	}
}

type appConfig struct {
	Version    int                       `json:"version"`
	JoinedAt   time.Time                 `json:"joinedAt"`
	Interfaces map[string]interfaceModel `json:"interfaces"`
}

func (c *appConfig) printStatus() {
	table := uitable.New()
	table.MaxColWidth = 50
	table.AddRow("Interface", "Network", "Address", "Port", "Peers", "Endpoint")
	for _, iface := range c.Interfaces {
		table.AddRow(iface.Name, iface.JoinDevice.Network.Name,
			iface.JoinDevice.Device.Addr.String(), iface.ListenPort,
			len(iface.JoinDevice.Peers), iface.JoinDevice.Device.Endpoint)
	}
	fmt.Println(table)
	fmt.Println()
	for _, iface := range c.Interfaces {
		table := uitable.New()
		table.MaxColWidth = 50
		table.AddRow("Network", "Peer", "Address", "Endpoint", "Key")
		table.AddRow(iface.JoinDevice.Network.Name, iface.JoinDevice.Device.Name+" (this host)",
			iface.JoinDevice.Device.Addr.String(), iface.JoinDevice.Device.Endpoint,
			iface.JoinDevice.Device.PublicKey.String())
		for _, peer := range iface.JoinDevice.Peers {
			table.AddRow(iface.JoinDevice.Network.Name, peer.Name,
				peer.Addr.String(), peer.Endpoint, peer.PublicKey.String())
		}
		fmt.Println(table)
	}
}

type interfaceModel struct {
	ApiUrl     string                   `json:"apiUrl"`
	Num        int                      `json:"num"`
	Name       string                   `json:"name"`
	JoinDevice types.JoinDeviceResponse `json:"joinDevice"`
	ListenPort int                      `json:"listenPort"`
	Key        []byte                   `json:"key"`
}

func (m *interfaceModel) Config() *types.InterfaceConfig {
	isServer := m.JoinDevice.Device.Endpoint != ""
	var postUp string
	if isServer {
		postUp = `sysctl -w net.ipv4.ip_forward=1`
	}
	return &types.InterfaceConfig{
		Name:       m.Name,
		Address:    m.JoinDevice.Device.Addr,
		ListenPort: m.ListenPort,
		PrivateKey: m.Key,
		PostUp:     postUp,
		Peers:      peersModel(m.JoinDevice.Peers).Config(&m.JoinDevice.Network, m.JoinDevice.Device.Endpoint != ""),
	}
}

type peersModel []types.Device

func (p peersModel) Config(n *types.Network, isServer bool) []types.PeerConfig {
	var result []types.PeerConfig
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
			result = append(result, types.PeerConfig{
				Name:       p[i].Name,
				AllowedIPs: []types.Address{addr},
				PublicKey:  p[i].PublicKey,
				Endpoint:   p[i].Endpoint,
			})
		} else if p[i].Endpoint != "" {
			// If the interface is a client, then we only connect to servers.
			// AllowedIPs is used to determine routing available on the server
			// peer, so we use the peer's address CIDR.
			result = append(result, types.PeerConfig{
				Name:                p[i].Name,
				Endpoint:            p[i].Endpoint,
				AllowedIPs:          []types.Address{p[i].Addr},
				PublicKey:           p[i].PublicKey,
				PersistentKeepalive: 15, // TODO: configurable?
			})
		}
	}
	return result
}

func newAppConfig() *appConfig {
	return &appConfig{
		Version:    1,
		JoinedAt:   time.Now().UTC(),
		Interfaces: map[string]interfaceModel{},
	}
}

func (c *appConfig) joinDevice(joinResp *types.JoinDeviceResponse, key types.Key, apiUrl string, listenPort int) {
	if iface, ok := c.Interfaces[joinResp.Device.Id]; ok {
		iface.JoinDevice = *joinResp
		if apiUrl != "" {
			iface.ApiUrl = apiUrl
		}
		if listenPort != 0 {
			iface.ListenPort = listenPort
		}
		// TODO: intelligent merge of response w/local interface config?
		// for example, if response is missing the token, don't clobber it?
		c.Interfaces[joinResp.Device.Id] = iface
	} else {
		ifaceNum := c.nextIfaceNum()
		ifaceName := fmt.Sprintf("wgn%03d", ifaceNum)
		c.Interfaces[joinResp.Device.Id] = interfaceModel{
			ApiUrl:     apiUrl,
			Num:        ifaceNum,
			Name:       ifaceName,
			ListenPort: listenPort,
			JoinDevice: *joinResp,
			Key:        key,
		}
	}
}

func (c *appConfig) departDevice(ifaceModel *interfaceModel) {
	delete(c.Interfaces, ifaceModel.JoinDevice.Device.Id)
}

func (c *appConfig) nextIfaceNum() int {
	var i int
	for _, ifaceModel := range c.Interfaces {
		if ifaceModel.Num > i {
			i = ifaceModel.Num
		}
	}
	i++
	return i
}

func (a *App) Join(ctx context.Context, name, networkName, endpoint string) error {
	err := a.checkDataDir()
	if err != nil {
		return errors.WithStack(err)
	}
	cfg, err := a.readConfig()
	if err != nil {
		if os.IsNotExist(errors.Cause(err)) {
			cfg = newAppConfig()
		} else {
			return errors.WithStack(err)
		}
	}

	if name == "" {
		name, err = os.Hostname()
		if err != nil {
			return errors.Wrap(err, "cannot determine hostname, node name is required")
		}
	}

	if networkName == "" {
		networkName = "default"
	}

	machineId, err := MachineId()
	if err != nil {
		return errors.Wrap(err, "cannot determine machine ID")
	}

	key, err := types.GenerateKey()
	if err != nil {
		return errors.Wrap(err, "failed to generate key")
	}

	// TODO: only really need to do this if we're starting a new network.
	availNet, err := network.RandomSubnetV4()
	if err != nil {
		return errors.Wrap(err, "failed to find an available subnet")
	}
	availAddr, err := types.ParseAddress(availNet)
	if err != nil {
		return errors.Wrapf(err, "failed to parse network %q", availNet)
	}

	listenPort, err := findListenPort(endpoint)
	if err != nil {
		return errors.Wrapf(err, "failed to find an available listen port")
	}

	cl := client.New(a.url)
	joinResp, err := cl.JoinDevice(ctx, &types.JoinDeviceRequest{
		Name:          name,
		Network:       networkName,
		MachineId:     machineId,
		Key:           key.PublicKey(),
		Endpoint:      endpoint,
		AvailableAddr: *availAddr,
		AvailablePort: 51820,
	})
	if err != nil {
		if errors.Is(err, client.ErrDeviceAlreadyJoined) {
			zapctx.Info(ctx, "device already joined, refreshing")
			return a.Refresh(ctx, endpoint)
		}
		return errors.Wrap(err, "join failed")
	}
	zapctx.Debug(ctx, "join device response", zap.String("response", fmt.Sprintf("%+v", joinResp)))

	cfg.joinDevice(joinResp, key, a.url, listenPort)
	err = a.writeConfig(cfg)
	if err != nil {
		return errors.Wrap(err, "failed to write config")
	}

	err = a.applyConfig(cfg)
	if err != nil {
		return errors.Wrap(err, "failed to apply config")
	}

	return nil
}

func endpointPort(endpoint string) int {
	if endpoint != "" {
		if _, port, err := net.SplitHostPort(endpoint); err == nil {
			if portNum, err := strconv.Atoi(port); err == nil {
				return portNum
			}
		}
	}
	return 0
}

func findListenPort(endpoint string) (int, error) {
	if port := endpointPort(endpoint); port != 0 {
		return port, nil
	}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{
		Port: 0,
		IP:   net.ParseIP("0.0.0.0"),
	})
	if err != nil {
		return 0, errors.Wrap(err, "failed to create a udp listener, no ports available?")
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).Port, nil
}

func WithToken(ctx context.Context, token []byte) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, "token", token)
}

func (a *App) Refresh(ctx context.Context, endpoint string) error {
	cfg, err := a.readConfig()
	if err != nil {
		return errors.WithStack(err)
	}
	if len(cfg.Interfaces) == 0 {
		return errors.New("not joined to any networks")
	}
	for _, ifaceModel := range cfg.Interfaces {
		apiUrl := a.url
		if ifaceModel.ApiUrl != "" {
			apiUrl = ifaceModel.ApiUrl
		}
		cl := client.New(apiUrl)
		zapctx.Debug(ctx, "refresh", zap.String("interface", fmt.Sprintf("%+v", ifaceModel)))
		// TODO: bulk API call for this?
		joinResp, err := cl.RefreshDevice(WithToken(ctx, ifaceModel.JoinDevice.Token), &types.RefreshDeviceRequest{
			Endpoint: endpoint,
		})
		if err != nil {
			return errors.Wrap(err, "refresh failed")
		}
		cfg.joinDevice(joinResp, ifaceModel.Key, apiUrl, endpointPort(endpoint))
	}

	err = a.writeConfig(cfg)
	if err != nil {
		return errors.Wrap(err, "failed to write updated config")
	}

	err = a.applyConfig(cfg)
	if err != nil {
		return errors.Wrap(err, "failed to apply config")
	}

	return nil
}

func (a *App) Depart(ctx context.Context, network string) error {
	cfg, err := a.readConfig()
	if err != nil {
		return errors.WithStack(err)
	}
	if len(cfg.Interfaces) == 0 {
		return errors.New("not joined to any networks")
	}
	var departed bool
	for _, ifaceModel := range cfg.Interfaces {
		apiUrl := a.url
		if apiUrl == "" {
			apiUrl = ifaceModel.ApiUrl
		}
		cl := client.New(apiUrl)
		if network != "" && network != ifaceModel.JoinDevice.Network.Name {
			continue
		}
		err := cl.DepartDevice(WithToken(ctx, ifaceModel.JoinDevice.Token))
		if err != nil {
			return errors.Wrap(err, "depart failed")
		}
		cfg.departDevice(&ifaceModel)
		departed = true
	}
	if !departed {
		return errors.New("no matching networks to depart from")
	}
	err = a.writeConfig(cfg)
	if err != nil {
		return errors.Wrap(err, "failed to write updated config")
	}
	err = a.applyConfig(cfg)
	if err != nil {
		return errors.Wrap(err, "failed to apply config")
	}
	return nil
}

func (a *App) Status(ctx context.Context) error {
	cfg, err := a.readConfig()
	if err != nil {
		return errors.WithStack(err)
	}
	if len(cfg.Interfaces) == 0 {
		return errors.New("not joined to any networks")
	}
	cfg.printStatus()
	return nil
}

func (a *App) writeConfig(cfg *appConfig) error {
	f, err := os.Create(a.dataDir + "/device.json")
	if err != nil {
		return errors.Wrap(err, "failed to create config")
	}
	defer f.Close()
	if err := json.NewEncoder(f).Encode(cfg); err != nil {
		return errors.Wrap(err, "failed to encode config")
	}
	return nil
}

func (a *App) readConfig() (*appConfig, error) {
	f, err := os.Open(a.dataDir + "/device.json")
	if err != nil {
		return nil, errors.Wrap(err, "failed to open config")
	}
	defer f.Close()
	var cfg appConfig
	err = json.NewDecoder(f).Decode(&cfg)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode config")
	}
	return &cfg, nil
}

func (a *App) applyConfig(cfg *appConfig) error {
	var errs []error
	confFilenames := map[string]bool{}
	for _, ifaceModel := range cfg.Interfaces {
		err := func() error {
			confFilename := a.dataDir + "/" + ifaceModel.Name + ".conf"
			f, err := os.Create(confFilename)
			if err != nil {
				return errors.Wrap(err, "failed to create interface device config")
			}
			confFilenames[confFilename] = true
			defer f.Close()
			ifaceCfg := ifaceModel.Config()
			err = ifaceCfg.WriteConfig(f)
			if err != nil {
				return errors.Wrap(err, "failed to write interface device config")
			}
			err = a.downUp(&ifaceModel, f.Name())
			if err != nil {
				return errors.Wrapf(err, "failed to bring up network interface %q", ifaceCfg.Name)
			}
			return nil
		}()
		if err != nil {
			log.Printf("%v", err)
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return errs[len(errs)-1]
	}

	// Clean up no-longer-configured interfaces
	allConfFilenames, err := filepath.Glob(a.dataDir + "/*.conf")
	if err != nil {
		errs = append(errs, err)
	} else {
		for i := range allConfFilenames {
			if confFilenames[allConfFilenames[i]] {
				continue
			}
			cmd := exec.Command(installRoot()+"/usr/bin/wg-quick", "down", allConfFilenames[i])
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			err := cmd.Run() // might error if already down
			if err != nil {
				log.Println(err)
			}
			err = os.Remove(allConfFilenames[i])
			if err != nil {
				log.Println(err)
			}
		}
	}

	cfg.printStatus()
	return nil
}

func installRoot() string {
	if snap := os.Getenv("SNAP"); snap != "" {
		return snap
	}
	return ""
}

func (a *App) downUp(ifaceCfg *interfaceModel, cfgPath string) error {
	cmd := exec.Command(installRoot()+"/usr/bin/wg-quick", "down", cfgPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run() // might error if already down
	if err != nil {
		log.Println(err)
	}
	cmd = exec.Command(installRoot()+"/usr/bin/wg-quick", "up", cfgPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func (a *App) checkDataDir() error {
	err := os.MkdirAll(a.dataDir, 0700)
	if err != nil {
		return errors.Wrapf(err, "failed to create data directory %q", a.dataDir)
	}
	check := a.dataDir + "/.check"
	f, err := os.Create(check)
	if err != nil {
		return errors.Wrapf(err, "cannot write to data directory %q", a.dataDir)
	}
	defer f.Close()
	defer os.Remove(check)
	return nil
}

func MachineId() ([]byte, error) {
	buf, err := ioutil.ReadFile("/etc/machine-id")
	if err != nil {
		return nil, errors.Wrap(err, "failed to read machine-id")
	}
	id, err := hex.DecodeString(strings.TrimSpace(string(buf)))
	if err != nil {
		return nil, errors.Wrapf(err, "invalid machine-id %q", string(buf))
	}
	mac := hmac.New(sha256.New, id)
	mac.Write([]byte("wiregarden"))
	return mac.Sum(nil), nil
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
