package setup

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
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

const ManualNssInstructions = `
The Wiregarden NSS plugin is not packaged for your platform. See
https://github.com/wiregarden-io/nss-wiregarden#install for other installation
options.
`

// TODO: It'd be nice to have a latest release URL that redirects.
const libnssDebURL = `https://github.com/wiregarden-io/nss-wiregarden/releases/download/v0.1.3/libnss-wiregarden_0.1.3+1599411942_amd64.deb`

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

func EnsureNssPluginInstalled(ctx context.Context) error {
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
	case "debian", "ubuntu":
		err = installNssDeb(ctx)
	default:
		err = errors.Wrapf(ErrUnsupportedPlatform, "linux distribution %q", id)
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

func installNssDeb(ctx context.Context) error {
	// Install ca-certificates before downloading, otherwise the TLS download
	// may fail. Might as well also install the sqlite library dependency up
	// front.
	err := execAll(exec.Command("apt-get", "install", "-y", "ca-certificates", "libsqlite3-0"))
	if err != nil {
		return errors.WithStack(err)
	}
	resp, err := http.Get(libnssDebURL)
	if err != nil {
		return errors.Wrapf(err, "failed to download package")
	}
	defer resp.Body.Close()
	f, err := ioutil.TempFile("", "")
	if err != nil {
		return errors.WithStack(err)
	}
	defer os.Remove(f.Name())
	defer f.Close()
	_, err = io.Copy(f, resp.Body)
	if err != nil {
		return errors.WithStack(err)
	}
	return execAll(exec.Command("dpkg", "-i", f.Name()))
}
