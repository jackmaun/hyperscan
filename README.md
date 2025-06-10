# hyperscan

**hyperscan** is a memory and disk artifact scanner built for offensive security assessments. It scans `.vmem` and `.vmdk` files for sensitive data like credentials, tokens, registry hives, NTLM hashes, and DPAPI material.

---

### Features

- Scan local `.vmem` or `.vmdk` memory/disk images
- Auto-discover VM files in common Windows directories
- Remote scanning over SMB and WinRM (username/password auth)
- Carves out registry hives (SAM, SYSTEM, SECURITY)
- Extracts and scans archives from remote hosts

---

### Installation

```bash
go build -o hyperscan
```

---

### Usage

```bash
hyperscan scan --input ./memory.vmem
hyperscan scan --input ./disk.vmdk --out ./loot
```

```bash
# Auto-scan local common VM directories
hyperscan scan --auto
```

```bash
# Scan remote host using SMB and WinRM (Windows creds required)
hyperscan scan --remote --host 192.168.1.100 --username Administrator --password 'CrazyPassword14!'
```

---

### Options

```bash
--input, -i        Path to VMEM or VMDK file
--out, -o          Output directory (default: ./output)
--auto             Automatically search local VM file locations
--remote           Enable remote scanning via WinRM + SMB
--host             Remote host IP or name
--username         Remote login username
--password         Remote login password
```

---

### Author
Jack Maunsell
CyberMaxx Offensive Security Intern

---

### TODO
- Live system memory scanning via agents
- Plugin support for custom extractors
- Optional JSON output
