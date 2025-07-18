package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "hyperscan",
	Short: "Hyperscan - offline memory and disk artifact scanner",
	Long:  "Hyperscan scans virtual memory and disk images for sensitive artifacts like passwords, tokens, and secrets.",

	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		printBanner();
	},
}

func init() {
	rootCmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		printBanner()
		_ = cmd.Usage()
	})
}
func Execute(){
	if err := rootCmd.Execute(); err != nil {
		fmt.Println("Error:", err)
	}
}

func AddCommand(cmd *cobra.Command){
	rootCmd.AddCommand(cmd)
}

func printBanner() {
	fmt.Println(`
  _                                               
 | |__  _   _ _ __   ___ _ __ ___  ___ __ _ _ __  
 | '_ \| | | | '_ \ / _ \ '__/ __|/ __/ _' | '_ \ 
 | | | | |_| | |_) |  __/ |  \__ \ (_| (_| | | | |
 |_| |_|\__, | .__/ \___|_|  |___/\___\__,|_| |_|
        \___/|_|                                  

 hyperscan - VM artifact scanner
 
 Author : Jack Maunsell - CyberMaxx
 `)
}