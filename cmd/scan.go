package cmd

import (
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hirochachacha/go-smb2"
	"github.com/spf13/cobra"
	"github.com/jackmaun/hyperscan/scanners"
)

var inputPath string
var outputPath string
var autoScan bool
var remoteScan bool
var remoteHost string
var remoteUser string
var remotePass string

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan a memory or disk image for secrets",
	Run: func(cmd *cobra.Command, args []string) {
		if remoteScan {
			fmt.Println("[*] Starting remote scan via SMB2...")
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
				fmt.Println("[-] No .vmem or .vmdk files found in common locations.")
				return
			}
			for _, file := range files {
				fmt.Println("[+] Scanning:", file)
				err := scanners.ScanMemory(file, outputPath)
				if err != nil {
					fmt.Println("[-] Scan failed for", file, ":", err)
				}
			}
			return
		}

		if inputPath == "" {
			fmt.Println("[-] No input file specified. Use --input or --auto or --remote.")
			return
		}

		fmt.Println("Running scan on:", inputPath)
		err := scanners.ScanMemory(inputPath, outputPath)
		if err != nil {
			fmt.Println("Scan failed:", err)
		}
	},
}

func init() {
	scanCmd.Flags().StringVarP(&inputPath, "input", "i", "", "Path to VMEM or VMDK file")
	scanCmd.Flags().StringVarP(&outputPath, "out", "o", "./output", "Directory to write carved artifacts")
	scanCmd.Flags().BoolVar(&autoScan, "auto", false, "Automatically scan common VM file locations (Windows only)")
	scanCmd.Flags().BoolVar(&remoteScan, "remote", false, "Scan remotely via SMB2")
	scanCmd.Flags().StringVar(&remoteHost, "host", "", "Remote host IP or name")
	scanCmd.Flags().StringVar(&remoteUser, "username", "", "Remote username")
	scanCmd.Flags().StringVar(&remotePass, "password", "", "Remote password")
	AddCommand(scanCmd)
}

func getCommonVMPaths() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	return []string{
		filepath.Join(home, "Documents", "Virtual Machines"),
		filepath.Join(home, "VirtualBox VMs"),
		filepath.Join(home, "AppData", "Local", "Temp"),
		`C:\\ProgramData\\VMware`,
		`C:\\Program Files (x86)\\VMware\\VMware Workstation`,
		`C:\\VirtualBox VMs`,
		`D:\\VMs\\`,
	}
}

func findVMFiles() ([]string, error) {
	var found []string
	for _, base := range getCommonVMPaths() {
		_ = filepath.Walk(base, func(path string, info os.FileInfo, err error) error {
			if err == nil && !info.IsDir() && (strings.HasSuffix(strings.ToLower(path), ".vmem") || strings.HasSuffix(strings.ToLower(path), ".vmdk")) {
				found = append(found, path)
			}
			return nil
		})
	}
	return found, nil
}

func handleRemoteScan(host, user, pass string) error {
	conn, err := net.DialTimeout("tcp", host+":445", 5*time.Second)
	if err != nil {
		return fmt.Errorf("failed to connect to host: %w", err)
	}
	defer conn.Close()

	d := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     user,
			Password: pass,
		},
	}

	session, err := d.Dial(conn)
	if err != nil {
		return fmt.Errorf("failed to establish SMB session: %w", err)
	}
	defer session.Logoff()

	fs, err := session.Mount("C$")
	if err != nil {
		return fmt.Errorf("failed to mount C$ share: %w", err)
	}
	defer fs.Umount()

	fmt.Println("[*] Searching for .vmem/.vmdk files on remote system...")
	return walkAndScanRemote(fs, `\`, host)
}

func walkAndScanRemote(fs *smb2.Share, root, host string) error {
	entries, err := fs.ReadDir(root)
	if err != nil {
		return nil
	}

	for _, entry := range entries {
		fullPath := filepath.Join(root, entry.Name())

		if entry.IsDir() {
			err := walkAndScanRemote(fs, fullPath, host)
			if err != nil {
				fmt.Println("[-] Failed to scan subdirectory:", err)
			}
		} else {
			if strings.HasSuffix(strings.ToLower(entry.Name()), ".vmem") || strings.HasSuffix(strings.ToLower(entry.Name()), ".vmdk") {
				fmt.Printf("[+] Found: %s\n", fullPath)

				remoteFile, err := fs.Open(fullPath)
				if err != nil {
					fmt.Println("[-] Failed to open remote file:", err)
					continue
				}
				defer remoteFile.Close()

				localName := strings.ReplaceAll(strings.TrimPrefix(fullPath, `\`), `\`, `_`)
				localPath := filepath.Join(os.TempDir(), "hyperscan_"+localName)
				outFile, err := os.Create(localPath)
				if err != nil {
					fmt.Println("[-] Failed to create local file:", err)
					continue
				}

				_, err = io.Copy(outFile, remoteFile)
				outFile.Close()
				if err != nil {
					fmt.Println("[-] Failed to copy file:", err)
					continue
				}

				fmt.Printf("[*] Scanning %s...\n", localPath)
				err = scanners.ScanMemory(localPath, outputPath)
				if err != nil {
					fmt.Println("[-] Scan failed:", err)
				}
			}
		}
	}
	return nil
}

