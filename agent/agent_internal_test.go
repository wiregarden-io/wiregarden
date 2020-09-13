package agent

import (
	"os"
	"testing"

	qt "github.com/frankban/quicktest"
)

func TestCheckReadOnly(t *testing.T) {
	c := qt.New(t)
	dataDir := c.Mkdir()
	os.Chmod(dataDir, 0500)
	err := checkDataDir(dataDir)
	c.Assert(err, qt.IsNil)
}

func TestCheckConflict(t *testing.T) {
	c := qt.New(t)
	tmp := c.Mkdir()
	f, err := os.Create(tmp + "/foo")
	c.Assert(err, qt.IsNil)
	defer f.Close()
	err = checkDataDir(tmp + "/foo")
	c.Assert(err, qt.ErrorMatches, ".*not a directory.*")
}
