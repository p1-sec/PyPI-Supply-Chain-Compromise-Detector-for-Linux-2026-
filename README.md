# PyPI Supply Chain Compromise Detector for Linux (2026)

A comprehensive Linux forensic detection and incident response script for identifying Indicators of Compromise (IOCs) associated with the 2026 PyPI supply chain attacks, including malicious versions of `lightning`, `pytorch-lightning`, `durabletask`, and `litellm`.

The script performs package auditing, Bun runtime detection, `.pth` persistence analysis, C2 hunting, AI assistant configuration inspection, credential integrity checks, persistence detection, and incident response guidance.

---

## Overview

This project was developed to help security professionals, SOC analysts, DFIR teams, and system administrators detect traces of the large-scale PyPI supply chain compromises discovered in 2026.

The scanner focuses on the following compromised packages and campaigns:

- `lightning` 2.6.2 and 2.6.3
- `pytorch-lightning` 2.6.2 and 2.6.3
- `durabletask` 1.4.1 - 1.4.3
- `litellm` March 2026 compromise
- TeamPCP / Mini Shai-Hulud malware campaign

---

## Features

### Python Environment Discovery
- System Python detection
- Virtual environment detection
- pyenv discovery
- Conda environment discovery

### Malicious Package Detection
- Detects compromised versions of:
  - lightning
  - pytorch-lightning
  - durabletask
  - litellm

### Artifact Detection
- Bun runtime detection
- Bun stealer artifacts
- Hidden `_runtime` directories
- Pip cache investigation

### Persistence Hunting
- Shell profile inspection
- Cron job analysis
- Systemd service inspection
- Suspicious running process detection

### AI Assistant Poisoning Detection
Scans for malicious modifications in:

- `.cursorrules`
- `CLAUDE.md`
- `claude.md`
- Cursor configuration files

### Credential Exposure Review
Checks:

- AWS credentials
- Azure tokens
- GCP credentials
- Kubernetes configs
- SSH keys
- Environment secrets

### Threat Hunting
- Command and Control IOC detection
- DNS artifacts
- System logs inspection
- Journal analysis
- Active outbound connections review

### Additional Auditing
- Pip installation history
- Requirements files
- Tsinghua PyPI mirror configuration
- Incident response recommendations

---

## Usage

```bash
chmod +x pypi_compromise_detect_v2.sh

sudo bash pypi_compromise_detect_v2.sh
```

The forensic report will be generated at:

```bash
/tmp/pypi_compromise_<timestamp>.log
```

---

## Threat Intelligence References

### Lightning / PyTorch Lightning Supply Chain Compromise

Sonatype:
https://www.sonatype.com/blog/malicious-pytorch-lightning-packages-found-on-pypi

Snyk:
https://snyk.io/blog/lightning-pypi-compromise-bun-based-credential-stealer/

---

### DurableTask Supply Chain Compromise

StepSecurity:
https://www.stepsecurity.io/blog/microsofts-durabletask-pypi-package-compromised-in-supply-chain-attack

Safeguard:
https://safeguard.sh/resources/blog/durabletask-pypi-compromise-may-2026

---

### LiteLLM Supply Chain Compromise

Truesec:
https://www.truesec.com/hub/blog/malicious-pypi-package-litellm-supply-chain-compromise

---

### Official Security Advisory

NHS Cyber Alert:
https://digital.nhs.uk/cyber-alerts/2026/cc-4781

---

## Acknowledgements

This project was researched, developed, and completed with assistance from:

- Claude AI (Anthropic)  
  https://www.anthropic.com/claude

  Used for:
  - Threat intelligence research
  - Malware campaign analysis
  - Detection logic development
  - Documentation assistance

---

## Disclaimer

This tool is provided for defensive security, incident response, digital forensics, and threat hunting purposes only.

The authors assume no responsibility for misuse or damage caused by the use of this software.

Always validate findings manually and follow your organization's incident response procedures.

---

## License

MIT License

Feel free to use, modify, distribute, and improve this project with proper attribution.
