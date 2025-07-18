package extractors

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
)

var lsassHeader = []byte("lsass.exe")

func CarveLsass(data []byte, outDir string) ([]string, error) {
	var carvedFiles []string
	found := 0
	offset := 0

	for {
		index := bytes.Index(data[offset:], lsassHeader)
		if index == -1 {
			break
		}
		offset += index

		peOffset := findPEHeader(data, offset)
		if peOffset == -1 {
			offset += len(lsassHeader)
			continue
		}

		imageSize := getImageSize(data, peOffset)
		if imageSize == 0 {
			offset += len(lsassHeader)
			continue
		}

		end := peOffset + imageSize
		if end > len(data) {
			offset += len(lsassHeader)
			continue
		}

		chunk := data[peOffset:end]

		found++
		label := fmt.Sprintf("lsass-%d.dmp", found)
		outPath := filepath.Join(outDir, label)
		err := os.WriteFile(outPath, chunk, 0644)
		if err != nil {
			return nil, fmt.Errorf("failed to write lsass dump to %s: %w", outPath, err)
		}

		carvedFiles = append(carvedFiles, outPath)
		fmt.Printf("[+] Carved lsass.exe process memory to %s (offset: 0x%X, size: %d bytes)\n", outPath, peOffset, imageSize)
		offset = end
	}

	if found == 0 {
		fmt.Println("[-] No lsass.exe process memory found")
	}

	return carvedFiles, nil
}

func findPEHeader(data []byte, startOffset int) int {
	for i := startOffset; i >= 0; i-- {
		if i+2 > len(data) {
			continue
		}
		if bytes.Equal(data[i:i+2], []byte("MZ")) {
			return i
		}
	}
	return -1
}

func getImageSize(data []byte, peOffset int) int {
	if peOffset+0x3c+4 > len(data) {
		return 0
	}
	ntHeaderOffset := peOffset + int(binary.LittleEndian.Uint32(data[peOffset+0x3c:]))

	if ntHeaderOffset+0x50+4 > len(data) {
		return 0
	}

	return int(binary.LittleEndian.Uint32(data[ntHeaderOffset+0x50:]))
}