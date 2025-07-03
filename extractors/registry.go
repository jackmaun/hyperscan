package extractors

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
)

var regfHeader = []byte("regf")

func CarveRegistryHives(data []byte, outDir string) error {
	found := 0
	offset := 0

	for {
		index := bytes.Index(data[offset:], regfHeader)
		if index == -1 {
			break
		}
		offset += index

		if offset+0x10 > len(data) {
			offset += len(regfHeader)
			continue
		}

		hiveSize := int(uint32(data[offset+0x0C])|uint32(data[offset+0x0D])<<8|uint32(data[offset+0x0E])<<16|uint32(data[offset+0x0F])<<24)

		if hiveSize <= 0 || offset+hiveSize > len(data) {
			offset += len(regfHeader)
			continue
		}

		end := offset + hiveSize
		chunk := data[offset:end]

		label := classifyHive(chunk)
		found++
		if label == "" {
			label = fmt.Sprintf("hive-%d", found)
		}

		outPath := filepath.Join(outDir, label+".regf")
		err := os.WriteFile(outPath, chunk, 0644)
		if err != nil {
			return fmt.Errorf("failed to write hive to %s: %w", outPath, err)
		}

		fmt.Printf("[+] Carved %s hive to %s (offset: 0x%X, size: %d bytes)\n", label, outPath, offset, hiveSize)
		offset = end
	}

	if found == 0 {
		fmt.Println("[-] No registry hives found")
	}
	return nil
}


func classifyHive(chunk []byte) string {
	switch {
	case bytes.Contains(chunk, []byte("SAM\\Domains")):
		return "SAM"
	case bytes.Contains(chunk, []byte("ControlSet001\\Services")):
		return "SYSTEM"
	case bytes.Contains(chunk, []byte("PolicySecrets")) || bytes.Contains(chunk, []byte("NL$KM")):
		return "SECURITY"
	default:
		return ""
	}
}
