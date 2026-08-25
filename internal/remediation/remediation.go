package remediation

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/trueMati/serverguard/internal/executor"
)

type Runner struct {
	executor executor.Executor
}

func New(e executor.Executor) *Runner {
	return &Runner{
		executor: e,
	}
}
func (r *Runner) Apply(ctx context.Context, fixkey string) error {
	switch fixkey {
	case "enable-firewall":
		return r.enableFirewall(ctx)
	case "upgrade-packages":
		r.upgradePackages(ctx)
	case "ssh-hardening":
		r.sshHardening(ctx)
	default:
		return fmt.Errorf(
			"unknown remediation: %s", fixkey)
	}
	return nil
}
func (r *Runner) enableFirewall(
	ctx context.Context,
) error {
	commands := [][]string{
		{
			"ufw",
			"default",
			"deny",
			"incoming",
		},
		{
			"ufw",
			"default",
			"allow",
			"outgoing",
		},
		{
			"ufw",
			"allow",
			"22/tcp",
		},
		{
			"ufw",
			"--force",
			"enable",
		},
	}

	for _, command := range commands {
		if _, err := r.executor.Run(
			ctx,
			command[0],
			command[1:]...,
		); err != nil {
			return err
		}
	}

	return nil
}
func (r *Runner) upgradePackages(
	ctx context.Context,
) error {
	_, err := r.executor.Run(
		ctx,
		"bash",
		"-lc",
		"export DEBIAN_FRONTEND=noninteractive && "+
			"apt-get update && "+
			"apt-get upgrade -y",
	)

	return err
}
func (r *Runner) sshHardening(
	ctx context.Context,
) error {
	const path = "/etc/ssh/sshd_config.d/99-serverguard.conf"

	if err := backupFile(path); err != nil {
		return err
	}

	config := []byte(
		"# Managed by ServerGuard\n" +
			"PermitRootLogin no\n" +
			"PasswordAuthentication no\n",
	)

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}

	if err := os.WriteFile(
		path,
		config,
		0644,
	); err != nil {
		return err
	}
	if _, err := r.executor.Run(
		ctx,
		"sshd",
		"-t",
	); err != nil {
		_ = restoreBackup(path)

		return fmt.Errorf(
			"SSH configuration validation failed: %w",
			err,
		)
	}
	if _, err := r.executor.Run(
		ctx,
		"systemctl",
		"reload",
		"ssh",
	); err != nil {
		_ = restoreBackup(path)

		return fmt.Errorf(
			"failed to reload SSH: %w",
			err,
		)
	}

	return nil
}

func backupFile(
	path string,
) error {
	data, err := os.ReadFile(path)

	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}

		return err
	}

	backupDir := "/var/lib/serverguard/backups"

	if err := os.MkdirAll(
		backupDir,
		0700,
	); err != nil {
		return err
	}

	target := filepath.Join(
		backupDir,
		filepath.Base(path)+".bak",
	)

	return os.WriteFile(
		target,
		data,
		0600,
	)
}
func restoreBackup(
	path string,
) error {
	backupPath := filepath.Join(
		"/var/lib/serverguard/backups",
		filepath.Base(path)+".bak",
	)

	data, err := os.ReadFile(
		backupPath,
	)

	if err != nil {
		return err
	}

	return os.WriteFile(
		path,
		data,
		0644,
	)
}
