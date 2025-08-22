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
	"AWS Access Key":         regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	"JWT":                    regexp.MustCompile(`eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+`),
	"Password Key":           regexp.MustCompile(`(?i)password\s*=\s*[^\"]{4,}`),
	"NTLM Hash":              regexp.MustCompile(`[a-fA-F0-9]{32}:[a-fA-F0-9]{32}`),
	"NTLMv2 Hash":            regexp.MustCompile(`[a-zA-Z0-9_.\\-]+::[a-zA-Z0-9_.\\-]+:[a-fA-F0-9]{16}:[a-fA-F0-9]{32,256}:.+`),
	"NetNTLMv2 Challenge":    regexp.MustCompile(`[^\s:]+::[^\s:]+:[a-fA-F0-9]{16}:[a-fA-F0-9]{32,}`),
	"LM:NTLM Hash Pair":      regexp.MustCompile(`[a-fA-F0-9]{32}:[a-fA-F0-9]{32}`),
	"Kerberos KRB-CRED":      regexp.MustCompile(`KRB-CRED`),
	"Kerberos Ticket ASN.1":  regexp.MustCompile(`\x6e\x82[\x00-\xff]{2}\x30\x82`),
	"Kerberos Base64 Ticket": regexp.MustCompile(`(?:YII|doIF)[A-Za-z0-9+/=]{100,}`),
	"DPAPI GUID":             regexp.MustCompile(`(?i)\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}`),
	"DPAPI Blob":             regexp.MustCompile(`(?s)DPAPI.{64,}?`),
	"SSH Private Key":        regexp.MustCompile(`-----BEGIN ((EC|PGP|DSA|RSA|OPENSSH) )?PRIVATE KEY( BLOCK)?-----`),
	"Google Cloud API Key":   regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`),
	"Azure Client Secret":    regexp.MustCompile(`[a-zA-Z0-9\-_~\.]{40}`),
}

type patternJob struct {
	name string
	re   *regexp.Regexp
}

func ScanMemory(path string, outDir string, jsonOutput bool, threads int) (map[string]interface{}, error) {
	_ = os.MkdirAll(outDir, 0755)

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

	return scanMemoryCore(mmapData, outDir, threads, path)
}

func ScanMemoryFromBytes(data []byte, outDir string, threads int) (map[string]interface{}, error) {
	_ = os.MkdirAll(outDir, 0755)
	return scanMemoryCore(data, outDir, threads, "")
}

func scanMemoryCore(data []byte, outDir string, threads int, filePath string) (map[string]interface{}, error) {
	results := make(map[string]interface{})
	var mu sync.Mutex

	bar := pb.StartNew(len(data))
	bar.Set(pb.Bytes, true)

	var wg sync.WaitGroup
	wg.Add(5)

	go func() {
		defer wg.Done()
		carved, err := extractors.CarveBrowserData(data, outDir)
		if err == nil && len(carved) > 0 {
			mu.Lock()
			results["Carved Browser Databases"] = carved
			mu.Unlock()
		} else if err != nil {
			fmt.Println("[-] Browser data carving failed:", err)
		}
	}()

	go func() {
		defer wg.Done()
		jobs := make(chan patternJob, len(patterns))
		var pwg sync.WaitGroup
		for i := 0; i < threads; i++ {
			pwg.Add(1)
			go func() {
				defer pwg.Done()
				for job := range jobs {
					matches := job.re.FindAll(data, -1)
					if len(matches) > 0 {
						var out []string
						for _, m := range matches {
							out = append(out, string(m))
						}
						mu.Lock()
						results[job.name] = out
						mu.Unlock()
					}
					bar.Add(len(data) / len(patterns))
				}
			}()
		}
		for name, re := range patterns {
			jobs <- patternJob{name: name, re: re}
		}
		close(jobs)
		pwg.Wait()
	}()

	entropyCountCh := make(chan int, 1)
	go func() {
		defer wg.Done()
		c := scanEntropyRegions(data, 2048, 512, 7.5, results, &mu)
		entropyCountCh <- c
	}()

	go func() {
		defer wg.Done()
		var carved []string
		var err error
		if filePath != "" {
			carved, err = extractors.CarveRegistryHivesStream(filePath, outDir, 256<<20, 0x4000)
		} else {
			carved, err = extractors.CarveRegistryHives(data, outDir)
		}
		if err != nil {
			fmt.Println("[-] Registry carving failed:", err)
		}
		if len(carved) > 0 {
			mu.Lock()
			results["Carved Registry Hives"] = carved
			mu.Unlock()
		}
	}()

	go func() {
		defer wg.Done()
		carved, err := extractors.CarveLsass(data, outDir)
		if err == nil && len(carved) > 0 {
			mu.Lock()
			results["Carved LSASS Dumps"] = carved
			mu.Unlock()
		} else if err != nil {
			fmt.Println("[-] LSASS carving failed:", err)
		}
	}()

	wg.Wait()
	bar.Finish()

	select {
	case c := <-entropyCountCh:
		fmt.Printf("[*] High Entropy Regions: %d\n", c)
	default:
	}

	return results, nil
}

func scanEntropyRegions(data []byte, windowSize, step int, threshold float64, results map[string]interface{}, mu *sync.Mutex) int {
	if windowSize < 2048 {
		windowSize = 2048
	}
	if step <= 0 || step > windowSize/2 {
		step = windowSize / 4
	}
	count := 0
	for i := 0; i+windowSize <= len(data); i += step {
		window := data[i : i+windowSize]
		e := shannonEntropy(window)
		if e >= threshold {
			count++
		}
	}
	mu.Lock()
	results["High Entropy Regions"] = count
	mu.Unlock()
	return count
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
	n := float64(len(data))
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := c / n
		entropy -= p * math.Log2(p)
	}
	return entropy
}

