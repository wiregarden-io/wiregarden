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
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io/ioutil"
	"net"
	"strconv"
	"strings"

	"github.com/pkg/errors"
)

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
