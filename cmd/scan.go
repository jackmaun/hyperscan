package cmd

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hirochachacha/go-smb2"
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

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan a memory or disk image for secrets",
	Run: func(cmd *cobra.Command, args []string) {
		if remoteScan {
			fmt.Println("[*] Starting remote scan via WinRM...")
			err := handleRemoteScanWinRM(remoteHost, remoteUser, remotePass)
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
	scanCmd.Flags().BoolVar(&remoteScan, "remote", false, "Scan remotely via WinRM and SMB2")
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

func handleRemoteScanWinRM(host, user, pass string) error {
	endpoint := winrm.NewEndpoint(host, 5985, false, false, nil, nil, nil, 0)
	client, err := winrm.NewClient(endpoint, user, pass)
	if err != nil {
		return fmt.Errorf("failed to create WinRM client: %w", err)
	}

	zipPath := `C:\Users\Public\hyperscan.zip`
	powershell := fmt.Sprintf(`
		$files = Get-ChildItem -Path C:\ -Recurse -Include *.vmem,*.vmdk -ErrorAction SilentlyContinue
		if ($files.Count -gt 0) {
    			Compress-Archive -Path $files.FullName -DestinationPath "%s" -Force
		} else {
    			Write-Output "NO_MATCHES"
		}
		`, zipPath)

	var stdout, stderr bytes.Buffer
	cmd := fmt.Sprintf(`powershell -Command "%s"`, strings.ReplaceAll(powershell, `"`, `\"`))
	_, err = client.Run(cmd, &stdout, &stderr)
	if err != nil {
		return fmt.Errorf("WinRM command failed: %w", err)
	}

	if strings.Contains(stdout.String(), "NO_MATCHES") {
		fmt.Println("[-] No matching files found remotely.")
		return nil
	}

	conn, err := net.DialTimeout("tcp", host+":445", 5*time.Second)
	if err != nil {
		return fmt.Errorf("failed to connect to SMB: %w", err)
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
		return fmt.Errorf("failed to start SMB session: %w", err)
	}
	defer session.Logoff()

	fs, err := session.Mount("C$")
	if err != nil {
		return fmt.Errorf("failed to mount C$: %w", err)
	}
	defer fs.Umount()

	remoteFile := `Users\Public\hyperscan.zip`
	rf, err := fs.Open(remoteFile)
	if err != nil {
		return fmt.Errorf("could not open remote zip: %w", err)
	}
	defer rf.Close()

	localZip := filepath.Join(os.TempDir(), "hyperscan_downloaded.zip")
	lf, err := os.Create(localZip)
	if err != nil {
		return fmt.Errorf("could not create local zip: %w", err)
	}
	defer lf.Close()

	_, err = io.Copy(lf, rf)
	if err != nil {
		return fmt.Errorf("could not copy zip: %w", err)
	}

	fmt.Println("[+] Extracting and scanning contents...")
	return extractAndScan(localZip)
}

func extractAndScan(zipPath string) error {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("failed to open zip: %w", err)
	}
	defer r.Close()

	for _, f := range r.File {
		if f.FileInfo().IsDir() {
			continue
		}
		outPath := filepath.Join(os.TempDir(), "hyperscan_extracted_"+filepath.Base(f.Name))
		outFile, err := os.Create(outPath)
		if err != nil {
			fmt.Println("[-] Could not create:", outPath)
			continue
		}
		rc, err := f.Open()
		if err != nil {
			outFile.Close()
			fmt.Println("[-] Could not open zipped file:", f.Name)
			continue
		}
		_, err = io.Copy(outFile, rc)
		rc.Close()
		outFile.Close()
		if err != nil {
			fmt.Println("[-] Could not extract:", f.Name)
			continue
		}
		fmt.Println("[*] Scanning extracted file:", outPath)
		_ = scanners.ScanMemory(outPath, outputPath)
	}
	return nil
}

