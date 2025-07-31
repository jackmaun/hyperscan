package scanners

import (
	"fmt"
	"io"
	"net"
	"path/filepath"
	"regexp"
	"sync"

	"github.com/hirochachacha/go-smb2"
)

func ScanSMBShare(host, share, path, pattern, user, pass string, threads int) (map[string]interface{}, error) {
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
		walkSMB(fs, path, filePattern, fileChan)
	}()

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range fileChan {
				scanSMBFile(fs, path, results, mutex)
			}
		}()
	}

	wg.Wait()

	return results, nil
}

func walkSMB(fs *smb2.Share, path string, pattern *regexp.Regexp, fileChan chan<- string) {
	files, err := fs.ReadDir(path)
	if err != nil {
		fmt.Printf("[-] Failed to read directory %s: %v\n", path, err)
		return
	}

	for _, file := range files {
		fullPath := filepath.Join(path, file.Name())
		if file.IsDir() {
			walkSMB(fs, fullPath, pattern, fileChan)
		} else {
			if pattern.MatchString(file.Name()) {
				fileChan <- fullPath
			}
		}
	}
}

func scanSMBFile(fs *smb2.Share, path string, results map[string]interface{}, mutex *sync.Mutex) {
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
		fmt.Printf("[*] Skipping large file: %s (%d bytes)\n", path, fi.Size())
		return
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
