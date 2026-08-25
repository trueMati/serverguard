package scanner

import (
	"bufio"
	"context"
	"os"
	"strings"

	"github.com/trueMati/serverguard/internal/model"
)

type UserCheck struct{}

func NewUserCheck() *UserCheck {
	return &UserCheck{}
}
func (c *UserCheck) Run(ctx context.Context) model.Finding {
	file, err := os.Open("/etc/passwd")
	if err != nil {
		return model.Finding{
			ID:          "USR-001",
			Title:       "Unable to inspect users",
			Description: err.Error(),
			Severity:    model.SeverityMedium,
			Status:      model.StatusError,
		}
	}
	defer file.Close()
	var exteraRootUsers []string

	sc := bufio.NewScanner(file)

	for sc.Scan() {
		fields := strings.Split(sc.Text(), ":")
		if len(fields) < 3 {
			continue
		}
		username := fields[0]
		uid := fields[2]
		if uid == "0" && username != "root" {
			exteraRootUsers = append(exteraRootUsers, username)
		}
	}
	if len(exteraRootUsers) > 0 {
		return model.Finding{
			ID:    "USR-001",
			Title: "Additional UID 0 accounts found",
			Description: strings.Join(
				exteraRootUsers,
				", ",
			),
			Severity: model.SeverityCritical,
			Status:   model.StatusFail,
			Fixable:  false,
		}
	}
	return model.Finding{
		ID:          "USR-001",
		Title:       "No additional UID 0 accounts",
		Description: "Only the root account has UID 0.",
		Severity:    model.SeverityInfo,
		Status:      model.StatusPass,
	}
}
