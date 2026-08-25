package executor

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

type Result struct {
	Stdout   string
	Stderr   string
	ExitCode int
}
type Executor interface {
	Run(ctx context.Context, name string, args ...string) (Result, error)
}
type CommandExecutor struct{}

func (CommandExecutor) Run(ctx context.Context, name string, args ...string) (Result, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout strings.Builder
	var stderr strings.Builder

	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	exitCode := 0
	if cmd.ProcessState != nil {
		exitCode = cmd.ProcessState.ExitCode()
	}
	result := Result{
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		ExitCode: exitCode,
	}
	if err != nil {
		return result, fmt.Errorf(
			"command %s failed: %w",
			name,
			err,
		)
	}
	return result, nil
}
