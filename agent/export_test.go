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
	"crypto/rand"

	qt "github.com/frankban/quicktest"

	"github.com/wiregarden-io/wiregarden/agent/store"
)

func NewTestAgent(c *qt.C, cl Client, nm NetworkManager) (*Agent, *store.Store) {
	var k store.Key
	_, err := rand.Reader.Read(k[:])
	c.Assert(err, qt.IsNil)
	st, err := store.New(":memory:", k)
	c.Assert(err, qt.IsNil)
	return &Agent{
		dataDir: c.Mkdir(),
		apiUrl:  "https://wiregarden.io/api",
		st:      st,
		newApi:  func(string) Client { return cl },
		nm:      nm,
	}, st
}
