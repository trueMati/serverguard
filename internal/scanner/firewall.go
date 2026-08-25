package scanner

import (
	"context"
	"os/exec"
	"strings"

	"github.com/trueMati/serverguard/internal/executor"
	"github.com/trueMati/serverguard/internal/model"
)

type FireWallCheck struct {
	executor executor.Executor
}

func NewFireWallCheck(e executor.Executor) *FireWallCheck {
	return &FireWallCheck{
		executor: e,
	}
}

func (c *FireWallCheck) Run(ctx context.Context) model.Finding {
	if _, err := exec.LookPath("ufw"); err != nil {
		return model.Finding{
			ID:          "FW-001",
			Title:       "UFW is not installed",
			Description: "Ubuntu firewall manager UFW is missing.",
			Severity:    model.SeverityHigh,
			Status:      model.StatusFail,
			Fixable:     false,
		}
	}
	result, _ := c.executor.Run(ctx, "ufw", "status")
	if strings.Contains(strings.ToLower(result.Stdout), "status: active") {
		return model.Finding{
			ID:          "FW-001",
			Title:       "Firewall is active",
			Description: "UFW is active.",
			Severity:    model.SeverityInfo,
			Status:      model.StatusPass,
		}
	}
	return model.Finding{
		ID:          "FW-001",
		Title:       "Firewall is disabled",
		Description: "UFW is installed but inactive.",
		Severity:    model.SeverityHigh,
		Status:      model.StatusFail,
		Fixable:     true,
		FixKey:      "enable-firewall",
	}
}
