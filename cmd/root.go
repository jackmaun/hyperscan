package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "hyperscan",
	Short: "Hyperscan - offline memory and disk artifact scanner",
	Long:  "Hyperscan scans virtual memory and disk images for sensitive artifacts like passwords, tokens, and secrets.",
}

func Execute(){
	if err := rootCmd.Execute(); err != nil {
		fmt.Println("Error:", err)
	}
}

func AddCommand(cmd *cobra.Command){
	rootCmd.AddCommand(cmd)
}
