package agent

import (
	"os"
	"testing"

	qt "github.com/frankban/quicktest"
	"github.com/pkg/errors"
)

func TestCheckReadOnly(t *testing.T) {
	c := qt.New(t)
	dataDir := c.Mkdir()
	os.Chmod(dataDir, 0500)
	err := checkDataDir(dataDir)
	c.Assert(err, qt.ErrorMatches, `.*permission denied`)
	c.Assert(os.IsPermission(errors.Cause(err)), qt.IsTrue)
}
