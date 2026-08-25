package scanner

import (
	"context"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/trueMati/serverguard/internal/executor"
	"github.com/trueMati/serverguard/internal/model"
)

type SSHCheck struct {
	executor executor.Executor
}

func NewSSHCheck(e executor.Executor) *SSHCheck {
	return &SSHCheck{
		executor: e,
	}
}

func (c *SSHCheck) Run(ctx context.Context) model.Finding {
	if _, err := exec.LookPath("sshd"); err != nil {
		return model.Finding{
			ID:          "SSH-001",
			Title:       "OpenSSH server is not installed",
			Description: "sshd was not found on the system.",
			Severity:    model.SeverityHigh,
			Status:      model.StatusFail,
			Fixable:     false,
		}
	}
	result, err := c.executor.Run(ctx, "sshd", "-T")
	if err != nil {
		return model.Finding{
			ID:          "SSH-001",
			Title:       "Unable to inspect SSH configuration",
			Description: result.Stderr,
			Severity:    model.SeverityHigh,
			Status:      model.StatusError,
		}
	}
	config := parseKeyValueOutput(result.Stdout)
	var issues []string
	if strings.ToLower(config["permitrootlogin"]) != "no" {
		issues = append(issues, "root SSH login is enabled")
	}
	if strings.ToLower(config["passwordauthentication"]) == "yes" {
		issues = append(issues, "SSH password authentication is enabled")
	}
	if len(issues) == 0 {
		return model.Finding{
			ID:          "SSH-001",
			Title:       "SSH configuration passed",
			Description: "Root login and password authentication are disabled.",
			Severity:    model.SeverityInfo,
			Status:      model.StatusPass,
		}
	}
	safetofix := hasSafeSSHAccess()
	return model.Finding{
		ID:    "SSH-001",
		Title: "SSH hardening issues found",
		Description: strings.Join(
			issues,
			"; ",
		),
		Severity: model.SeverityHigh,
		Status:   model.StatusFail,
		Fixable:  safetofix,
		FixKey:   "ssh-hardening",
	}
}

func parseKeyValueOutput(
	output string,
) map[string]string {
	values := make(
		map[string]string,
	)
	for _, line := range strings.Split(
		output,
		"\n",
	) {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		values[fields[0]] = fields[1]
	}
	return values
}
func hasSafeSSHAccess() bool {
	sudoUser := os.Getenv("SUDO_USER")

	if sudoUser == "" || sudoUser == "root" {
		return false
	}

	u, err := user.Lookup(sudoUser)
	if err != nil {
		return false
	}

	authorizedKeys := filepath.Join(
		u.HomeDir,
		".ssh",
		"authorized_keys",
	)

	_, err = os.Stat(authorizedKeys)

	return err == nil
}
