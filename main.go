package main

import (
	"os"
	"github.com/fatih/color"
	"github.com/jackmaun/hyperscan/cmd"
)

func main(){
	color.Output = os.Stdout
	color.Error = os.Stderr
	cmd.Execute()
}
