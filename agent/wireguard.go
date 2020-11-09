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
	"log"
	"os"
	"os/exec"

	"github.com/pkg/errors"

	"github.com/wiregarden-io/wiregarden/agent/store"
)

var wireguardInstallPrefix = ""

func init() {
	if snap := os.Getenv("SNAP"); snap != "" {
		wireguardInstallPrefix = snap
	}
}

type wireguardManager struct {
	dataDir string
}

func (m *wireguardManager) EnsureInterface(iface *store.Interface) error {
	confFilename := m.dataDir + "/" + iface.Name() + ".conf"
	f, err := os.Create(confFilename)
	if err != nil {
		return errors.Wrap(err, "failed to create interface device config")
	}
	defer f.Close()
	ifaceCfg := iface.Config()
	err = ifaceCfg.WriteConfig(f)
	if err != nil {
		return errors.Wrap(err, "failed to write interface device config")
	}
	err = m.downUp(f.Name())
	if err != nil {
		return errors.Wrapf(err, "failed to bring up network interface %q", ifaceCfg.Name)
	}
	return nil
}

func (m *wireguardManager) RemoveInterface(iface *store.Interface) error {
	confFilename := m.dataDir + "/" + iface.Name() + ".conf"
	cmd := exec.Command(wireguardInstallPrefix+"/usr/bin/wg-quick", "down", confFilename)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run() // might error if already down
	if err != nil {
		log.Println(err)
	}
	err = os.Remove(confFilename)
	if err != nil {
		log.Println(err)
	}
	return nil
}

func (*wireguardManager) downUp(cfgPath string) error {
	cmd := exec.Command(wireguardInstallPrefix+"/usr/bin/wg-quick", "down", cfgPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run() // might error if already down
	if err != nil {
		log.Println(err)
	}
	cmd = exec.Command(wireguardInstallPrefix+"/usr/bin/wg-quick", "up", cfgPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
