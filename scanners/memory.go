package scanners

import (
	"fmt"
	"math"
	"os"
	"regexp"
	"sync"

	"github.com/cheggaaa/pb/v3"
	"github.com/edsrzf/mmap-go"
	"github.com/jackmaun/hyperscan/extractors"
)

var patterns = map[string]*regexp.Regexp{
	"AWS Access Key":            regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	"JWT":                       regexp.MustCompile(`eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+`),
	"Password Key":              regexp.MustCompile(`(?i)password\s*=\s*[^\"]{4,}`),
	"NTLM Hash":                 regexp.MustCompile(`[a-fA-F0-9]{32}:[a-fA-F0-9]{32}`),
	"NTLMv2 Hash":               regexp.MustCompile(`[a-zA-Z0-9_.\\-]+::[a-zA-Z0-9_.\\-]+:[a-fA-F0-9]{16}:[a-fA-F0-9]{32,256}:.+`),
	"NetNTLMv2 Challenge":       regexp.MustCompile(`[^\s:]+::[^\s:]+:[a-fA-F0-9]{16}:[a-fA-F0-9]{32,}`),
	"LM:NTLM Hash Pair":         regexp.MustCompile(`[a-fA-F0-9]{32}:[a-fA-F0-9]{32}`),
	"Kerberos KRB-CRED":         regexp.MustCompile(`KRB-CRED`),
	"Kerberos Ticket ASN.1":     regexp.MustCompile(`\x6e\x82[\x00-\xff]{2}\x30\x82`),
	"Kerberos Base64 Ticket":    regexp.MustCompile(`(?:YII|doIF)[A-Za-z0-9+/=]{100,}`),
	"DPAPI GUID":                regexp.MustCompile(`(?i)\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}`),
	"DPAPI Blob":                regexp.MustCompile(`(?s)\x01\x00\x00\x00.{80,700}`),
	"SSH Private Key":           regexp.MustCompile(`-----BEGIN ((EC|PGP|DSA|RSA|OPENSSH) )?PRIVATE KEY( BLOCK)?-----`),
	"Google Cloud API Key":      regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`),
	"Azure Client Secret":       regexp.MustCompile(`[a-zA-Z0-9\-_~\.]{40}`),
}

type patternJob struct {
	name string
	re   *regexp.Regexp
}

func ScanMemory(path string, outDir string, jsonOutput bool, threads int) (map[string]interface{}, error) {
	os.MkdirAll(outDir, 0755)
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	mmapData, err := mmap.Map(file, mmap.RDONLY, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to mmap file: %w", err)
	}
	defer mmapData.Unmap()

	return scanMemory(mmapData, outDir, threads)
}

func ScanMemoryFromBytes(data []byte, outDir string, threads int) (map[string]interface{}, error) {
	return scanMemory(data, outDir, threads)
}

func scanMemory(data []byte, outDir string, threads int) (map[string]interface{}, error) {
	results := make(map[string]interface{})
	var mutex = &sync.Mutex{}

	bar := pb.StartNew(len(data))
	bar.Set(pb.Bytes, true)

	var wg sync.WaitGroup
	wg.Add(5)

	go func() {
		defer wg.Done()
		carved, err := extractors.CarveBrowserData(data, outDir)
		if err != nil {
			fmt.Println("[-] Browser data carving failed:", err)
			return
		}
		if len(carved) > 0 {
			mutex.Lock()
			results["Carved Browser Databases"] = carved
			mutex.Unlock()
		}
	}()

	go func() {
		defer wg.Done()
		jobs := make(chan patternJob, len(patterns))
		var patternWg sync.WaitGroup
		for i := 0; i < threads; i++ {
			patternWg.Add(1)
			go func() {
				defer patternWg.Done()
				for job := range jobs {
					matches := job.re.FindAll(data, -1)
					if len(matches) > 0 {
						var stringMatches []string
						for _, m := range matches {
							stringMatches = append(stringMatches, string(m))
						}
						mutex.Lock()
						results[job.name] = stringMatches
						mutex.Unlock()
					}
					bar.Add(len(data) / len(patterns))
				}
			}()
		}
		for name, re := range patterns {
			jobs <- patternJob{name: name, re: re}
		}
		close(jobs)
		patternWg.Wait()
	}()

	go func() {
		defer wg.Done()
		scanEntropyRegions(data, 64, 32, 4.8, results, mutex)
	}()

	go func() {
		defer wg.Done()
		extractors.CarveRegistryHives(data, outDir)
	}()

	go func() {
		defer wg.Done()
		carved, err := extractors.CarveLsass(data, outDir)
		if err != nil {
			fmt.Println("[-] LSASS carving failed:", err)
			return
		}
		if len(carved) > 0 {
			mutex.Lock()
			results["Carved LSASS Dumps"] = carved
			mutex.Unlock()
		}
	}()

	wg.Wait()

	bar.Finish()

	return results, nil
}


func scanEntropyRegions(data []byte, windowSize, step int, threshold float64, results map[string]interface{}, mutex *sync.Mutex) {
	var highEntropyRegions []string
	for i := 0; i < len(data)-windowSize; i += step {
		window := data[i : i+windowSize]
		ent := shannonEntropy(window)
		if ent >= threshold {
			highEntropyRegions = append(highEntropyRegions, fmt.Sprintf("High entropy region (%.2f) at offset 0x%X", ent, i))
		}
	}
	if len(highEntropyRegions) > 0 {
		mutex.Lock()
		results["High Entropy Regions"] = highEntropyRegions
		mutex.Unlock()
	}
}

func shannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var freq [256]float64
	for _, b := range data {
		freq[b]++
	}
	var entropy float64
	length := float64(len(data))
	for _, count := range freq {
		if count == 0 {
			continue
		}
		p := count / length
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}