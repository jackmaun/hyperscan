# hyperscan
## Work in Progress

**hyperscan** is an offline memory and disk artifact scanner built for offensive security. It scans `.vmem` and `.vmdk` files for sensitive data like credentials, tokens, registry hives, and DPAPI material.

### Basic scan

```bash
hyperscan scan --input ./memory.vmem
hyperscan scan --input ./memory.vmem --out ./loot
