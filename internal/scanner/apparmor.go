package scanner

import (
	"context"
	"os/exec"

	"github.com/trueMati/serverguard/internal/executor"
	"github.com/trueMati/serverguard/internal/model"
)

type AppArmorCheck struct {
	executor executor.Executor
}

func NewAppArmorCheck(e executor.Executor) *AppArmorCheck {
	return &AppArmorCheck{
		executor: e,
	}
}

func (c *AppArmorCheck) Run(ctx context.Context) model.Finding {
	if _, err := exec.LookPath("aa-status"); err != nil {
		return model.Finding{
			ID:          "MAC-001",
			Title:       "AppArmor inspection unavailable",
			Description: "aa-status was not found.",
			Severity:    model.SeverityMedium,
			Status:      model.StatusError,
		}
	}
	_, err := c.executor.Run(ctx, "aa-status", "enabled")
	if err != nil {
		return model.Finding{
			ID:          "MAC-001",
			Title:       "AppArmor is not enabled",
			Description: "AppArmor does not report as enabled.",
			Severity:    model.SeverityHigh,
			Status:      model.StatusFail,
			Fixable:     false,
		}
	}
	return model.Finding{
		ID:          "MAC-001",
		Title:       "AppArmor is enabled",
		Description: "Mandatory access control is active.",
		Severity:    model.SeverityInfo,
		Status:      model.StatusPass,
	}
}
