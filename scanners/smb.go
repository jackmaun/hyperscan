package scanners

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/hirochachacha/go-smb2"
)

type fileInfo struct {
	path string
	size int64
}

func ScanSMBShare(host, share, path, pattern, user, pass string, threads int, progressChan chan<- int) (map[string]interface{}, error) {
	conn, err := net.Dial("tcp", host+":445")
	if err != nil {
		return nil, fmt.Errorf("failed to connect to SMB host: %w", err)
	}
	defer conn.Close()

	d := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     user,
			Password: pass,
		},
	}

	s, err := d.Dial(conn)
	if err != nil {
		return nil, fmt.Errorf("failed to dial SMB session: %w", err)
	}
	defer s.Logoff()

	fs, err := s.Mount(share)
	if err != nil {
		return nil, fmt.Errorf("failed to mount SMB share: %w", err)
	}
	defer fs.Umount()

	results := make(map[string]interface{})
	var mutex = &sync.Mutex{}
	var wg sync.WaitGroup

	fileChan := make(chan string)
	filePattern, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("invalid file pattern regex: %w", err)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(fileChan)
		var files []fileInfo
		walkSMB(fs, path, filePattern, &files)

		sort.Slice(files, func(i, j int) bool {
			return files[i].size < files[j].size
		})

		for _, file := range files {
			fileChan <- file.path
		}
	}()

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func(progressChan chan<- int) {
			defer wg.Done()
			for path := range fileChan {
				scanSMBFile(fs, path, results, mutex, progressChan)
				if progressChan != nil {
					progressChan <- 1
				}
			}
		}(progressChan)
	}

	wg.Wait()
	if progressChan != nil {
		close(progressChan)
	}

	return results, nil
}

func walkSMB(fs *smb2.Share, path string, pattern *regexp.Regexp, files *[]fileInfo) {
	items, err := fs.ReadDir(path)
	if err != nil {
		fmt.Printf("[-] Failed to read directory %s: %v\n", path, err)
		return
	}

	for _, item := range items {
		fullPath := filepath.Join(path, item.Name())
		if item.IsDir() {
			walkSMB(fs, fullPath, pattern, files)
		} else {
			if pattern.MatchString(item.Name()) {
				*files = append(*files, fileInfo{path: fullPath, size: item.Size()})
			}
		}
	}
}

func scanSMBFile(fs *smb2.Share, path string, results map[string]interface{}, mutex *sync.Mutex, progressChan chan<- int) {
	f, err := fs.Open(path)
	if err != nil {
		fmt.Printf("[-] Failed to open file %s: %v\n", path, err)
		return
	}
	defer f.Close()

	const maxFileSize = 100 * 1024 * 1024
	fi, err := f.Stat()
	if err != nil {
		fmt.Printf("[-] Failed to get file info for %s: %v\n", path, err)
		return
	}
	if fi.Size() > maxFileSize {
		fmt.Printf("[*] Large file found: %s (%d bytes)\n", path, fi.Size())
		fmt.Print("Choose an option: [S]can, [C]ontinue, [X]it: ")
		reader := bufio.NewReader(os.Stdin)
		input, _ := reader.ReadString('\n')
		input = strings.ToLower(strings.TrimSpace(input))

		switch input {
		case "s":
            fmt.Print("Enter number of threads for scanning: ")
            reader := bufio.NewReader(os.Stdin)
            threadInput, _ := reader.ReadString('\n')
            threads, err := strconv.Atoi(strings.TrimSpace(threadInput))
            if err != nil {
                fmt.Println("[-] Invalid input for threads, defaulting to 1")
                threads = 1
            }

            content, err := io.ReadAll(f)
            if err != nil {
                fmt.Printf("[-] Failed to read file %s: %v\n", path, err)
                return
            }

            outDir := "./output"

            memResults, err := ScanMemoryFromBytes(content, outDir, threads)
            if err != nil {
                fmt.Printf("[-] Memory scan for %s failed: %v\n", path, err)
                return
            }

            mutex.Lock()
            for k, v := range memResults {
                results[k] = v
            }
            mutex.Unlock()
            return

		case "c":
			fmt.Printf("[*] Skipping file: %s\n", path)
			return
		case "x":
			fmt.Println("[-] Scan cancelled by user.")
			os.Exit(0)
		default:
			fmt.Printf("[*] Invalid input. Skipping file: %s\n", path)
			return
		}
	}

	content, err := io.ReadAll(f)
	if err != nil {
		fmt.Printf("[-] Failed to read file %s: %v\n", path, err)
		return
	}

	for name, re := range patterns {
		matches := re.FindAll(content, -1)
		if len(matches) > 0 {
			var stringMatches []string
			for _, m := range matches {
				stringMatches = append(stringMatches, fmt.Sprintf("%s: %s", path, string(m)))
			}
			mutex.Lock()
			if _, ok := results[name]; !ok {
				results[name] = []string{}
			}
			results[name] = append(results[name].([]string), stringMatches...)
			mutex.Unlock()
		}
	}
}
