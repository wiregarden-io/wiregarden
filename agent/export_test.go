package agent

import (
	"crypto/rand"

	qt "github.com/frankban/quicktest"

	"github.com/wiregarden-io/wiregarden/agent/store"
)

func NewTestAgent(c *qt.C, api Client, nm NetworkManager) (*Agent, *store.Store) {
	var k store.Key
	_, err := rand.Reader.Read(k[:])
	c.Assert(err, qt.IsNil)
	st, err := store.New(":memory:", k)
	c.Assert(err, qt.IsNil)
	return &Agent{
		dataDir: c.Mkdir(),
		apiUrl:  "https://wiregarden.io/api",
		st:      st,
		api:     api,
		nm:      nm,
	}, st
}
