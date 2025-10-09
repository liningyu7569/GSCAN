package cmd

import (
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "goscan",
	Short: "Network Scanner",
}

var ScanCmd = &cobra.Command{
	Use:   "scan [target]",
	Short: "Scan target IP",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		//target := args[0]
		//alive,err := scanner.PingHost(target)
	},
}
