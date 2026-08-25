package scanner

import (
	"context"
	"strings"

	"github.com/trueMati/serverguard/internal/executor"
	"github.com/trueMati/serverguard/internal/model"
)

type PortsCheck struct {
	executor executor.Executor
}

func NewPortsCheck(e executor.Executor) *PortsCheck {
	return &PortsCheck{
		executor: e,
	}
}
func (c *PortsCheck) Run(ctx context.Context) model.Finding {
	result, err := c.executor.Run(ctx, "ss", "-lnt")
	if err != nil {
		return model.Finding{
			ID:          "NET-001",
			Title:       "Unable to inspect listening ports",
			Description: result.Stderr,
			Severity:    model.SeverityMedium,
			Status:      model.StatusError,
		}
	}
	var ports []string

	for _, line := range strings.Split(result.Stdout, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		localAddres := fields[3]

		index := strings.LastIndex(
			localAddres,
			":",
		)
		if index == -1 {
			continue
		}
		port := localAddres[index+1:]
		if port != "" {
			ports = append(ports, port)
		}
	}
	return model.Finding{
		ID:    "NET-001",
		Title: "Listening TCP ports detected",
		Description: strings.Join(
			ports,
			", ",
		),
		Severity: model.SeverityInfo,
		Status:   model.StatusPass,
	}
}
