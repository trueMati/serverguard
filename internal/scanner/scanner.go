package scanner

import (
	"context"

	"github.com/trueMati/serverguard/internal/executor"
	"github.com/trueMati/serverguard/internal/model"
)

type Check interface {
	Run(ctx context.Context) model.Finding
}
type Scanner struct {
	checks []Check
}

func New(e executor.CommandExecutor) *Scanner {
	return &Scanner{
		checks: []Check{
			NewOsCheck(),
			NewSSHCheck(e),
			NewFireWallCheck(e),
			NewPackageCheck(e),
			NewUserCheck(),
			NewAppArmorCheck(e),
			NewPortsCheck(e),
		},
	}
}
func (s *Scanner) Run(ctx context.Context) []model.Finding {
	findings := make([]model.Finding, 0, len(s.checks))
	for _, check := range s.checks {
		findings = append(findings, check.Run(ctx))
	}
	return findings
}
