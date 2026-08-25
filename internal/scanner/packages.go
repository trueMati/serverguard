package scanner

import (
	"bufio"
	"context"
	"strings"

	"github.com/trueMati/serverguard/internal/executor"
	"github.com/trueMati/serverguard/internal/model"
)

type PackageCheck struct {
	executor executor.Executor
}

func NewPackageCheck(e executor.Executor) *PackageCheck {
	return &PackageCheck{
		executor: e,
	}
}
func (c *PackageCheck) Run(ctx context.Context) model.Finding {
	result, err := c.executor.Run(ctx, "bash", "-lc", "apt list --upgradable 2>/dev/null | tail -n +2")
	if err != nil {
		return model.Finding{
			ID:          "PKG-001",
			Title:       "Unable to inspect package updates",
			Description: result.Stderr,
			Severity:    model.SeverityMedium,
			Status:      model.StatusError,
		}
	}
	count := 0
	sc := bufio.NewScanner(
		strings.NewReader(
			strings.TrimSpace(result.Stdout),
		),
	)
	for sc.Scan() {
		if strings.TrimSpace(sc.Text()) != "" {
			count++
		}
	}
	if count == 0 {
		return model.Finding{
			ID:          "PKG-001",
			Title:       "System packages are up to date",
			Description: "No pending package updates were found.",
			Severity:    model.SeverityInfo,
			Status:      model.StatusPass,
		}
	}

	return model.Finding{
		ID:          "PKG-001",
		Title:       "Pending package updates",
		Description: "There are pending package updates.",
		Severity:    model.SeverityHigh,
		Status:      model.StatusFail,
		Fixable:     true,
		FixKey:      "upgrade-packages",
	}
}
