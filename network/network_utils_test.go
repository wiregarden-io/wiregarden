// Copyright 2020 Cmars Technologies LLC.
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.

package network

import (
	"testing"

	qt "github.com/frankban/quicktest"
)

func TestRandomSubnetV4(t *testing.T) {
	c := qt.New(t)
	addrs := map[string]bool{}
	for i := 0; i < 10; i++ {
		addr, err := RandomSubnetV4()
		c.Assert(err, qt.IsNil)
		addrs[addr] = true
	}
	c.Assert(addrs, qt.HasLen, 10)
}
