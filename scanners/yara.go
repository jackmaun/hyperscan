package scanners

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	yara "github.com/hillu/go-yara/v4"
)

type yaraMatchCollector struct {
	matches []string
}

func (yc *yaraMatchCollector) RuleMatching(_ *yara.ScanContext, r *yara.Rule) (bool, error) {
	yc.matches = append(yc.matches, r.Identifier())
	return true, nil
}

func (yc *yaraMatchCollector) RuleNotMatching(_ *yara.ScanContext, _ *yara.Rule) (bool, error) {
	return true, nil
}

func (yc *yaraMatchCollector) TooManyMatches(_ *yara.ScanContext, _ *yara.Rule) (bool, error) {
	return false, nil
}

func ScanYara(path string, rulesPath string, outDir string, jsonOutput bool, threads int) (map[string]interface{}, error) {
	os.MkdirAll(outDir, 0755)

	compiler, err := yara.NewCompiler()
	if err != nil {
		return nil, fmt.Errorf("[-] Failed to create YARA compiler: %w", err)
	}

	err = filepath.Walk(rulesPath, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return fmt.Errorf("[-] Failed to access rule path %s: %w", p, err)
		}
		if info.IsDir() {
			return nil
		}
		if ext := filepath.Ext(p); ext == ".yar" || ext == ".yara" {
			fmt.Printf("[*] Loading YARA rule: %s\n", p)

			f, err := os.Open(p)
			if err != nil {
				return fmt.Errorf("[-] Failed to open rule file %s: %w", p, err)
			}
			defer f.Close()
			if err := compiler.AddFile(f, ""); err != nil {
				return fmt.Errorf("[-] Failed to add YARA rule file %s: %w", p, err)
			}
			fmt.Printf("[+] Loaded YARA rule file: %s\n", filepath.Base(p))
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("[-] Failed to walk rule directory: %w", err)
	}

	rules, err := compiler.GetRules()
	if err != nil {
		return nil, fmt.Errorf("[-] Failed to compile YARA rules: %w", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("[-] Failed to read input file: %w", err)
	}

	fmt.Printf("[*] Running YARA scan on %s (size: %d bytes)...\n", filepath.Base(path), len(data))

	collector := &yaraMatchCollector{}
	if err := rules.ScanMem(data, 0, 5*time.Second, collector); err != nil {
		return nil, fmt.Errorf("[-] YARA scan failed: %w", err)
	}

	results := make(map[string]interface{})
	if len(collector.matches) > 0 {
		fmt.Printf("[+] YARA matches found: %v\n", collector.matches)
		results["YARA Matches"] = collector.matches
	} else {
		fmt.Printf("[-] No YARA rule matches found\n")
	}

	return results, nil
}
