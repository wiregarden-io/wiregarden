package setup

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"

	"github.com/acobaugh/osrelease"
	"github.com/juju/zaputil/zapctx"
	"github.com/pkg/errors"
)

const ManualPackageInstructions = `
Unable to install wireguard for your platform.

Install Wireguard following the instructions for your platform at
https://www.wireguard.com/install/.
`

var ErrUnsupportedPlatform = fmt.Errorf("unsupported platform")

func CheckPlatformSupport() error {
	if runtime.GOOS != "linux" {
		return errors.Wrapf(ErrUnsupportedPlatform, "OS %q", runtime.GOOS)
	}
	osrelease, err := osrelease.Read()
	if err != nil {
		return errors.Wrapf(err, "failed to read os-release")
	}
	id, ok := osrelease["ID"]
	if !ok {
		return errors.Errorf("invalid os-release, missing ID")
	}
	switch id {
	case "debian", "fedora", "ubuntu":
		return nil
	default:
		if strings.HasPrefix(id, "opensuse-") {
			return nil
		}
	}
	return errors.Wrapf(ErrUnsupportedPlatform, "linux distribution %q", id)
}

func EnsureWireguardInstalled(ctx context.Context) error {
	err := CheckPlatformSupport()
	if err != nil {
		return errors.WithStack(err)
	}
	osrelease, err := osrelease.Read()
	if err != nil {
		return errors.Wrapf(err, "failed to read os-release")
	}
	id, ok := osrelease["ID"]
	if !ok {
		return errors.Errorf("invalid os-release, missing ID")
	}
	switch id {
	case "debian":
		err = execAll(
			exec.Command("apt-get", "update"),
			exec.Command("apt-get", "install", "-y", "wireguard"),
		)
		if err != nil {
			zapctx.Warn(ctx, `
Failed to install wireguard. You might need to enable backports and try again.
See https://backports.debian.org/Instructions/.
`)
		}
	case "fedora":
		err = execAll(
			exec.Command("dnf", "-y", "install", "wireguard-tools"),
		)
	case "ubuntu":
		err = execAll(
			exec.Command("apt-get", "update"),
			exec.Command("apt-get", "install", "-y", "wireguard"),
		)
	default:
		if strings.HasPrefix(id, "opensuse-") {
			err = execAll(
				exec.Command("zypper", "--non-interactive", "install", "wireguard-tools"),
			)
		} else {
			return errors.Wrapf(ErrUnsupportedPlatform, "linux distribution %q", id)
		}
	}
	return errors.WithStack(err)
}

func execAll(cmds ...*exec.Cmd) error {
	for i := range cmds {
		out, err := cmds[i].CombinedOutput()
		if err != nil {
			return errors.Wrapf(err, "command failed, output: %s", string(out))
		}
	}
	return nil
}
