package cmd

import(
	"fmt"
	"github.com/spf13/cobra"
	"github.com/jackmaun/hyperscan/scanners"
)

var inputPath string
var outputPath string

var scanCmd = &cobra.Command{
	Use: "scan",
	Short: "Scan a memory or disk image for secrets",
	Run: func(cmd *cobra.Command, args []string){
		fmt.Println("Running scan on:", inputPath)
		err := scanners.ScanMemory(inputPath, outputPath)
		if err != nil {
			fmt.Println("Scan failed:", err)
		}
	},
}

func init(){
	scanCmd.Flags().StringVarP(&inputPath, "input", "i", "", "Path to VNEM or VMDK file")
	scanCmd.Flags().StringVarP(&outputPath, "out", "o", "./output", "Directory to write carved artifacts")
	scanCmd.MarkFlagRequired("input")
	AddCommand(scanCmd)
}
