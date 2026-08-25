package scanner

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/trueMati/serverguard/internal/model"
)

type OSCheck struct{}

func NewOsCheck() *OSCheck {
	return &OSCheck{}
}

func ParseOsRelease(content string) map[string]string {
	values := make(map[string]string)

	for _, line := range strings.Split(
		content,
		"\n",
	) {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		values[parts[0]] = strings.Trim(parts[1], `"`)

	}
	return values
}
func (c *OSCheck) Run(ctx context.Context) model.Finding {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return model.Finding{
			ID:          "SYS-001",
			Title:       "Unable to detect operating system",
			Description: err.Error(),
			Severity:    model.SeverityCritical,
			Status:      model.StatusError,
		}
	}
	values := ParseOsRelease(string(data))
	if values["ID"] != "ubuntu" {
		return model.Finding{
			ID:    "SYS-001",
			Title: "Unsupported operating system",
			Description: fmt.Sprintf(
				"Detected OS: %s. ServerGuard v0.1 supports Ubuntu only.",
				values["ID"],
			),
			Severity: model.SeverityCritical,
			Status:   model.StatusFail,
		}
	}
	return model.Finding{
		ID:    "SYS-001",
		Title: "Supported Ubuntu detected",
		Description: fmt.Sprintf(
			"Ubuntu %s detected.",
			values["VERSION_ID"],
		),
		Severity: model.SeverityInfo,
		Status:   model.StatusPass,
	}
}
