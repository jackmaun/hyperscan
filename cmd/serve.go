package cmd

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/jackmaun/hyperscan/scanners"
	"github.com/spf13/cobra"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Run hyperscan in server mode for remote scanning",
	Long:  `Run hyperscan in server mode for remote scanning. This is not intended to be used directly by users.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("[*] Starting hyperscan server on port 8080...")
		http.HandleFunc("/scan", handleScanRequest)
		http.ListenAndServe(":8080", nil)
	},
}

func handleScanRequest(w http.ResponseWriter, r *http.Request) {
	filePath := r.URL.Query().Get("path")
	if filePath == "" {
		http.Error(w, "missing path parameter", http.StatusBadRequest)
		return
	}

	results, err := scanners.ScanMemory(filePath, "/tmp/hyperscan", true)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

func init() {
	AddCommand(serveCmd)
}
