package scanners

import (
	"fmt"
	"os"
	"regexp"
	"github.com/jackmaun/hyperscan/extractors"
	"github.com/edsrzf/mmap-go"
)

var patterns = map[string]*regexp.Regexp{
	"AWS Access Key": regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	"JWT Token":      regexp.MustCompile(`eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+`),
	"Password Key":   regexp.MustCompile(`(?i)password\s*=\s*[^\s"]{4,}`),
	"NTLM Hash":      regexp.MustCompile(`[a-fA-F0-9]{32}:[a-fA-F0-9]{32}`), // placeholder for now
}

func ScanMemory(path string, outDir string) error {
	os.MkdirAll(outDir, 0755)
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	mmapData, err := mmap.Map(file, mmap.RDONLY, 0)
	if err != nil {
		return fmt.Errorf("failed to mmap file: %w", err)
	}
	defer mmapData.Unmap()

	fmt.Printf("Scanning memory file (size: %d bytes)...\n", len(mmapData))

	for name, re := range patterns {
		matches := re.FindAll(mmapData, -1)
		if len(matches) > 0 {
			fmt.Println("[+] Found %d %s matches:\n", len(matches), name)
			for _, m := range matches {
				fmt.Println("	", string(m))
			}
		}
	}
	fmt.Println("Carving for registry hives...")
	err = extractors.CarveRegistryHives(mmapData, outDir)
	if err != nil {
		fmt.Println("Carving Failed:", err)
	}
	return nil
}
