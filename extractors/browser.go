package extractors

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
)

func CarveBrowserData(data []byte, outDir string) ([]string, error) {
	var carvedFiles []string

	sqliteHeader := []byte("SQLite format 3\x00")

	indexes := findAll(data, sqliteHeader)

	for _, index := range indexes {
		end := index + 1024*1024
		if end > len(data) {
			end = len(data)
		}

		searchEnd := end
		if searchEnd > len(data) {
			searchEnd = len(data)
		}
		potentialEnd := bytes.LastIndex(data[index:searchEnd], []byte("sqlite_master"))
		if potentialEnd != -1 {
			end = index + potentialEnd + 200
		}
		if end > len(data) {
			end = len(data)
		}

		carvedData := data[index:end]

		outPath := filepath.Join(outDir, fmt.Sprintf("carved_browser_db_%d.sqlite", index))

		err := os.WriteFile(outPath, carvedData, 0644)
		if err != nil {
			fmt.Printf("[-] Failed to write carved browser data to %s: %v\n", outPath, err)
			continue
		}

		carvedFiles = append(carvedFiles, outPath)
	}

	return carvedFiles, nil
}

func findAll(data, subslice []byte) []int {
	var indexes []int
	for i := 0; i < len(data); {
		index := bytes.Index(data[i:], subslice)
		if index == -1 {
			break
		}
		indexes = append(indexes, i+index)
		i += index + 1
	}
	return indexes
}
