package cmd

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/trueMati/serverguard/internal/executor"
	"github.com/trueMati/serverguard/internal/model"
	"github.com/trueMati/serverguard/internal/remediation"
	"github.com/trueMati/serverguard/internal/scanner"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan the server for security issues",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		reader := bufio.NewReader(os.Stdin)
		return runScan(reader)
	},
}

func runScan(reader *bufio.Reader) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("ServerGuard must be run as root; use: sudo serverguard")
	}
	ctx := context.Background()

	exec := executor.CommandExecutor{}
	sc := scanner.New(exec)
	fmt.Println()
	fmt.Println("Starting ServerGuard security scan...")
	fmt.Println()

	finding := sc.Run(ctx)
	sort.SliceStable(finding, func(i, j int) bool {
		return finding[i].Severity > finding[j].Severity
	})
	printResults(finding)

	fixable := getFixableFindings(finding)
	if len(fixable) == 0 {
		fmt.Println()
		fmt.Println("No automatic fixes are available.")
		return nil
	}
	fmt.Println()
	fmt.Printf(
		"%d automatic fix(es) are available.\n",
		len(fixable),
	)

	fmt.Println()
	fmt.Println("The following changes may be applied:")
	for _, finding := range fixable {
		fmt.Printf(
			"  - [%s] %s\n",
			finding.Severity,
			finding.Title,
		)
	}

	fmt.Println()
	fmt.Print("Apply these fixes? [y/N]: ")

	answer, err := reader.ReadString('\n')
	if err != nil {
		return err
	}

	answer = strings.TrimSpace(
		strings.ToLower(answer),
	)

	if answer != "y" && answer != "yes" {
		fmt.Println()
		fmt.Println("No changes were made.")
		return nil
	}

	if err := applyFixes(ctx, exec, fixable); err != nil {
		return err
	}

	// Always re-run the scanner after remediation.
	fmt.Println()
	fmt.Println("Re-scanning server...")
	fmt.Println()

	finalFindings := sc.Run(ctx)

	printResults(finalFindings)

	fmt.Println()
	fmt.Println("ServerGuard scan completed.")

	return nil
}

func printResults(findings []model.Finding) {
	fmt.Println("===================================")
	fmt.Println("          SCAN RESULTS")
	fmt.Println("===================================")
	fmt.Println()

	for _, finding := range findings {
		status := "PASS"

		if finding.Status == model.StatusFail {
			status = "FAIL"
		}

		if finding.Status == model.StatusError {
			status = "ERROR"
		}

		fmt.Printf(
			"[%s] [%s] %s\n",
			status,
			finding.Severity,
			finding.Title,
		)

		fmt.Printf(
			"    %s\n",
			finding.Description,
		)

		if finding.Fixable {
			fmt.Println(
				"    Auto-fix: available",
			)
		}

		fmt.Println()
	}
}

func getFixableFindings(
	findings []model.Finding,
) []model.Finding {
	var result []model.Finding

	for _, finding := range findings {
		if finding.Status == model.StatusFail &&
			finding.Fixable &&
			finding.FixKey != "" {
			result = append(result, finding)
		}
	}

	return result
}
func applyFixes(
	ctx context.Context,
	exec executor.Executor,
	findings []model.Finding,
) error {
	runner := remediation.New(exec)

	fmt.Println()
	fmt.Println("Applying security fixes...")
	fmt.Println()

	for _, finding := range findings {
		fmt.Printf(
			"[%s] %s\n",
			finding.ID,
			finding.Title,
		)

		if err := runner.Apply(
			ctx,
			finding.FixKey,
		); err != nil {
			fmt.Printf(
				"    FAILED: %v\n",
				err,
			)
			continue
		}

		fmt.Println("    OK")
	}
	return nil
}
func init() {
	rootCmd.AddCommand(scanCmd)

}
