package daemon

import (
	"context"
	"html/template"
	"os"
	"os/exec"

	"github.com/juju/zaputil/zapctx"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

const (
	serviceTmpl = `
[Unit]
Description=Wiregarden agent

[Service]
ExecStart={{.BinaryPath}} daemon run
Restart=on-failure
RestartSec=1
User=root

[Install]
WantedBy=multi-user.target
`
	servicePath = "/lib/systemd/system/wiregarden.service"
	systemctl   = "/bin/systemctl"
)

func Install() error {
	t, err := template.New("service").Parse(serviceTmpl)
	if err != nil {
		return errors.Wrap(err, "failed to parse systemd service template")
	}
	f, err := os.Create(servicePath)
	if err != nil {
		return errors.Wrap(err, "failed to open systemd service file")
	}
	defer f.Close()
	binPath, err := os.Executable()
	if err != nil {
		return errors.Wrap(err, "failed to read executable path of running process")
	}
	err = t.Execute(f, struct {
		BinaryPath string
	}{
		BinaryPath: binPath,
	})
	if err != nil {
		return errors.Wrap(err, "failed to render systemd service file")
	}
	err = daemonReload()
	if err != nil {
		return errors.Wrap(err, "failed to reload systemd services")
	}
	err = enableService()
	if err != nil {
		return errors.Wrap(err, "failed to enable service")
	}
	err = restartService()
	if err != nil {
		return errors.Wrap(err, "failed to start service")
	}
	return nil
}

func daemonReload() error {
	return exec.Command(systemctl, "daemon-reload").Run()
}

func enableService() error {
	return exec.Command(systemctl, "enable", "wiregarden").Run()
}

func restartService() error {
	return exec.Command(systemctl, "restart", "wiregarden").Run()
}

func Uninstall(ctx context.Context) error {
	err := stopService()
	if err != nil {
		zapctx.Debug(ctx, "failed to stop service", zap.Error(err))
	}
	err = disableService()
	if err != nil {
		zapctx.Debug(ctx, "failed to disable service", zap.Error(err))
	}
	err = os.RemoveAll(servicePath)
	if err != nil {
		return errors.Wrap(err, "failed to remove service file")
	}
	err = daemonReload()
	if err != nil {
		return errors.Wrap(err, "failed to reload systemd services")
	}
	return nil
}

func stopService() error {
	return exec.Command(systemctl, "stop", "wiregarden").Run()
}

func disableService() error {
	return exec.Command(systemctl, "disable", "wiregarden").Run()
}
