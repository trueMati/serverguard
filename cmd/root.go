package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

const version = "v0.0.1"

var rootCmd = &cobra.Command{
	Use:     "serverguard",
	Short:   "Linux server security hardening tool",
	Version: version,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runMainMenu()
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "Error", err)
		os.Exit(1)
	}
}

func runMainMenu() error {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Println()
		fmt.Println("===================================")
		fmt.Printf("         ServerGuard %s\n", version)
		fmt.Println("===================================")
		fmt.Println()
		fmt.Println("1) Scan")
		fmt.Println("2) Exit")
		fmt.Println()
		fmt.Print("Select an option: ")

		input, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		input = strings.TrimSpace(input)

		switch input {
		case "1":
			return runScan(reader)
		case "2":
			fmt.Println("Goodbye")
			return nil
		default:
			fmt.Println("Invalid option")
		}

	}
}
func init() {
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
