package extractors

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
)

func CarveBrowserData(data []byte, outDir string) ([]string, error) {
	var carvedFiles []string

	sqliteHeader := []byte("SQLite format 3\x00")

	indexes := findAll(data, sqliteHeader)

	for _, index := range indexes {
		if index+100 > len(data) {
			continue
		}

        var pageSize uint32
        buf := bytes.NewReader(data[index+16 : index+18])
        err := binary.Read(buf, binary.BigEndian, &pageSize)
        if err != nil {
            fmt.Printf("[-] Error reading page size at offset %d: %v\n", index, err)
            continue
        }

        if pageSize == 1 {
            pageSize = 65536
        }

		dbSize := 0
		for pageNum := 0; ; pageNum++ {
			pageStart := index + pageNum*int(pageSize)
			if pageStart >= len(data) {
				break
			}

			if pageNum > 0 && data[pageStart] == 0x00 {
				break
			}
			dbSize = (pageNum + 1) * int(pageSize)
		}

		if dbSize == 0 {
			continue
		}

		end := index + dbSize
		if end > len(data) {
			end = len(data)
		}

		carvedData := data[index:end]

		outPath := filepath.Join(outDir, fmt.Sprintf("carved_browser_db_%d.sqlite", index))

		err = os.WriteFile(outPath, carvedData, 0644)
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
