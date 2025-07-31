package cmd

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/fatih/color"
	"github.com/jackmaun/hyperscan/scanners"
	"github.com/masterzen/winrm"
	"github.com/spf13/cobra"
)

var inputPath string
var outputPath string
var autoScan bool
var remoteScan bool
var remoteHost string
var remoteUser string
var remotePass string
var smbScan bool
var smbShare string
var smbSharePath string
var smbFilePattern string
var jsonOutput bool
var threads int

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan a memory or disk image for secrets",
	Run: func(cmd *cobra.Command, args []string) {
		if yaraRulesPath != "" {
			fmt.Println("[*] Starting YARA scan...")
			results, err := scanners.ScanYara(inputPath, yaraRulesPath, outputPath, jsonOutput, threads)
			if err != nil {
				fmt.Println("[-] YARA scan failed:", err)
				return
			}
			printResults(results, jsonOutput)
			return
		}

		if smbScan {
			err := handleSMBScan(remoteHost, smbShare, smbSharePath, smbFilePattern, remoteUser, remotePass, threads)
			if err != nil {
				fmt.Println("[-] SMB scan failed:", err)
			}
			return
		}

		if remoteScan {
			fmt.Println("[*] Starting remote scan...")
			err := handleRemoteScan(remoteHost, remoteUser, remotePass)
			if err != nil {
				fmt.Println("[-] Remote scan failed:", err)
			}
			return
		}

		if autoScan {
			fmt.Println("[*] Auto-scanning common VM file locations...")
			files, err := findVMFiles()
			if err != nil {
				fmt.Println("[-] Error while scanning paths:", err)
				return
			}
			if len(files) == 0 {
				fmt.Println("[-] No supported files found in common locations.")
				return
			}
			for _, file := range files {
				fmt.Println("[+] Scanning:", file)
				results, err := scanners.ScanMemory(file, outputPath, jsonOutput, threads)
				if err != nil {
					fmt.Println("[-] Scan failed for", file, ":", err)
				}
				printResults(results, jsonOutput)
			}
			return
		}

		if inputPath == "" && !autoScan && !remoteScan && !smbScan {
			fmt.Println("[-] No input file specified. Use --input, --auto, --remote, or --smb.")
			return
		}

		fmt.Println("Running scan on:", inputPath)
		results, err := scanners.ScanMemory(inputPath, outputPath, jsonOutput, threads)
		if err != nil {
			fmt.Println("Scan failed:", err)
		}
		printResults(results, jsonOutput)
	},
}

func init() {
	scanCmd.Flags().StringVarP(&inputPath, "input", "i", "", "Path to memory or disk image file (e.g., .vmem, .vmdk, .vdi, .vhd, .vhdx, .raw, .dd)")
	scanCmd.Flags().StringVarP(&outputPath, "out", "o", "./output", "Directory to write carved artifacts")
	scanCmd.Flags().BoolVar(&autoScan, "auto", false, "Automatically scan common VM file locations (Windows only)")
	scanCmd.Flags().BoolVar(&remoteScan, "remote", false, "Scan remotely via SMB or WinRM")
	scanCmd.Flags().StringVar(&remoteHost, "host", "", "Remote host IP or name")
	scanCmd.Flags().StringVar(&remoteUser, "username", "", "Remote username")
	scanCmd.Flags().StringVar(&remotePass, "password", "", "Remote password")
	scanCmd.Flags().BoolVar(&smbScan, "smb", false, "Scan a remote SMB share")
	scanCmd.Flags().StringVar(&smbShare, "share", "", "SMB share path (e.g., C$/Users)")
	scanCmd.Flags().StringVar(&smbSharePath, "share-path", ".", "Path within the SMB share to start scanning")
	scanCmd.Flags().StringVar(&smbFilePattern, "file-pattern", ".*", "Regex pattern to filter files to scan")
	scanCmd.Flags().BoolVar(&jsonOutput, "json", false, "Enable JSON output")
	scanCmd.Flags().IntVarP(&threads, "threads", "t", 1, "Number of threads for parallel scanning")
	AddCommand(scanCmd)
}

func getCommonVMPaths() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	paths := []string{
		filepath.Join(home, "Documents", "Virtual Machines"),
		filepath.Join(home, "VirtualBox VMs"),
		filepath.Join(home, "AppData", "Local", "Temp"),
		`C:\ProgramData\VMware`,
		`C:\Program Files (x86)\VMware\VMware Workstation`,
		`C:\VirtualBox VMs`,
		`D:\VMs\`,
	}

	hypervBase := `C:\ProgramData\Microsoft\Windows\Hyper-V\Virtual Machines`
	_ = filepath.Walk(hypervBase, func(path string, info os.FileInfo, err error) error {
		if err == nil && info.IsDir() {
			if matched, _ := regexp.MatchString(`[a-fA-F0-9\-]{36}`, info.Name()); matched {
				paths = append(paths, path)
			}
		}
		return nil
	})

	return paths
}

func findVMFiles() ([]string, error) {
	var found []string
	filePattern := regexp.MustCompile(`(?i)\.(vmem|vmdk|vdi|vhd|vhdx|raw|dd|bin|vsv|avhdx)$`)
	paths := getCommonVMPaths()

	for _, base := range paths {
		fmt.Println("[*] Searching:", base)
		_ = filepath.Walk(base, func(path string, info os.FileInfo, err error) error {
			if err == nil && !info.IsDir() && filePattern.MatchString(path) {
									if info.Size() > 64*1024*1024 { 
						fmt.Println("    [+] Found candidate:", path, "-", fmt.Sprintf("%.1f MB", float64(info.Size())/1024.0/1024.0))
						found = append(found, path)
					} else {
						fmt.Println("    [-] Skipping small file:", path)
					}
			}
			return nil
		})
	}
	return found, nil
}

func handleRemoteScan(host, user, pass string) error {
	endpoint := winrm.NewEndpoint(host, 5985, false, false, nil, nil, nil, 0)
	client, err := winrm.NewClient(endpoint, user, pass)
	if err != nil {
		return fmt.Errorf("failed to create WinRM client: %w", err)
	}

	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}
	remotePath := `C:\Users\Public\hyperscan.exe`

	exeContent, err := os.ReadFile(exePath)
	if err != nil {
		return fmt.Errorf("failed to read executable: %w", err)
	}

	encodedExe := base64.StdEncoding.EncodeToString(exeContent)

	uploadCmd := fmt.Sprintf("powershell -Command \"[System.IO.File]::WriteAllBytes('%s', [System.Convert]::FromBase64String('%s'))\"", remotePath, encodedExe)

	var stdout, stderr bytes.Buffer
	_, err = client.Run(uploadCmd, &stdout, &stderr)
	if err != nil {
		return fmt.Errorf("failed to upload hyperscan binary: %w\nStdout: %s\nStderr: %s", err, stdout.String(), stderr.String())
	}

	startServerCmd := fmt.Sprintf("powershell -Command \"Start-Process -FilePath %s -ArgumentList 'serve'\"", remotePath)
	_, err = client.Run(startServerCmd, &stdout, &stderr)
	if err != nil {
		return fmt.Errorf("failed to start hyperscan server: %w\nStdout: %s\nStderr: %s", err, stdout.String(), stderr.String())
	}

	fmt.Println("[*] Hyperscan server started on remote host.")

	remoteFiles, err := findRemoteVMFiles(client)
	if err != nil {
		return fmt.Errorf("failed to find remote VM files: %w", err)
	}

	if len(remoteFiles) == 0 {
		fmt.Println("[-] No supported files found on remote system.")
		return nil
	}

	for _, file := range remoteFiles {
		fmt.Printf("[*] Scanning remote file: %s\n", file)
		scanURL := fmt.Sprintf("http://%s:8080/scan?path=%s", host, file)
		resp, err := http.Get(scanURL)
		if err != nil {
			fmt.Printf("[-] Failed to scan remote file %s: %v\n", file, err)
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			bodyBytes, _ := io.ReadAll(resp.Body)
			fmt.Printf("[-] Remote scan for %s failed with status %d: %s\n", file, resp.StatusCode, string(bodyBytes))
			continue
		}

		var results map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
			fmt.Printf("[-] Failed to decode JSON response for %s: %v\n", file, err)
			continue
		}
		printResults(results, jsonOutput)
	}

	return nil
}

func handleSMBScan(host, share, path, pattern, user, pass string, threads int) error {
	fmt.Println("[*] Starting SMB scan...")
	results, err := scanners.ScanSMBShare(host, share, path, pattern, user, pass, threads)
	if err != nil {
		return fmt.Errorf("SMB scan failed: %w", err)
	}
	printResults(results, jsonOutput)
	return nil
}

func findRemoteVMFiles(client *winrm.Client) ([]string, error) {
	powershell := `
		$files = @()
		$commonPaths = @(
			"$env:USERPROFILE\\Documents\\Virtual Machines",
			"$env:USERPROFILE\\VirtualBox VMs",
			"$env:TEMP",
			"C:\\ProgramData\\VMware",
			"C:\\Program Files (x86)\\VMware\\VMware Workstation",
			"C:\\VirtualBox VMs",
			"C:\\ProgramData\\Microsoft\\Windows\\Hyper-V\\Virtual Machines",
			"D:\\VMs\\"
		)
		foreach ($base in $commonPaths) {
			if (Test-Path $base) {
				$files += Get-ChildItem -Path $base -Recurse -Include *.vmem,*.vmdk,*.vdi,*.vhd,*.vhdx,*.raw,*.dd,*.bin,*.vsv,*.avhdx -ErrorAction SilentlyContinue | Where-Object { $_.Length -gt 67108864 } | Select-Object -ExpandProperty FullName
			}
		}
		$files | ConvertTo-Json
	`

	var stdout, stderr bytes.Buffer
	cmd := fmt.Sprintf(`powershell -Command "%s"`, strings.ReplaceAll(powershell, `"`, `\"`))
	_, err := client.Run(cmd, &stdout, &stderr)
	if err != nil {
		return nil, fmt.Errorf("WinRM command failed: %w\nStdout: %s\nStderr: %s", err, stdout.String(), stderr.String())
	}

	var remoteFiles []string
	if err := json.Unmarshal(stdout.Bytes(), &remoteFiles); err != nil {
		return nil, fmt.Errorf("failed to unmarshal remote files JSON: %w\nOutput: %s", err, stdout.String())
	}

	return remoteFiles, nil
}

func printResults(results map[string]interface{}, jsonOutput bool) {
	if jsonOutput {
		jsonBytes, err := json.MarshalIndent(results, "", "  ")
		if err != nil {
			color.Red("[-] Failed to marshal results to JSON:", err)
			return
		}
		fmt.Println(string(jsonBytes))
	} else {
		for name, matches := range results {
			if stringSlice, ok := matches.([]string); ok {
				fmt.Printf("[+] Found %d %s matches:\n", len(stringSlice), name)
				for _, m := range stringSlice {
					fmt.Println("    ", m)
				}
			}
		}
	}
}

