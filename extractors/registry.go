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
			fmt.Printf("[-] Skipping regf at 0x%X: not enough data for size field\n", offset)
			offset += len(regfHeader)
			continue
		}

		hiveSize := int(uint32(data[offset+0x0C])|uint32(data[offset+0x0D])<<8|uint32(data[offset+0x0E])<<16|uint32(data[offset+0x0F])<<24)

		if hiveSize <= 0 || offset+hiveSize > len(data) {
			fmt.Printf("[-] Skipping regf at 0x%X: invalid size (%d bytes)\n", offset, hiveSize)
			offset += len(regfHeader)
			continue
		}

		hbinOffset := offset + 0x1000
		if hbinOffset+4 > len(data) || !bytes.Equal(data[hbinOffset:hbinOffset+4], []byte("hbin")) {
			fmt.Printf("[-] Skipping regf at 0x%X: missing 'hbin' at offset 0x%X\n", offset, hbinOffset)
			offset += len(regfHeader)
			continue
		}

		chunk := data[offset : offset+hiveSize]

		if !bytes.Contains(chunk, []byte("nk")) {
			fmt.Printf("[-] Skipping regf at 0x%X: missing 'nk' record\n", offset)
			offset += len(regfHeader)
			continue
		}

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
		offset += hiveSize
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

