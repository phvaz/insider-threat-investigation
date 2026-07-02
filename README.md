# Insider Threat Investigation — NexChain Exchange

> **BLUEPRINT — WORK IN PROGRESS**
> This document is a planning reference. It will be replaced by the final README upon project completion.

---

## Case Overview

| Field | Value |
|---|---|
| Case reference | ITI-2026-001 |
| Scenario | Insider threat — suspected data exfiltration at a fictional crypto exchange |
| Target organization | NexChain Exchange (fictional) |
| Target system | Windows 10 Enterprise LTSC (clean installation) |
| Investigator | Paulo Vaz |
| Status | In progress |

---

## Scenario

A compliance analyst at NexChain Exchange is suspected of exfiltrating customer KYC data (names, documents, wallet addresses) prior to resignation. The analyst allegedly copied sensitive files to an external device and attempted to cover their tracks using anti-forensic techniques. A forensic investigation was initiated to determine whether exfiltration occurred and reconstruct the full activity timeline.

---

## Lab Environment

| Component | Details |
|---|---|
| Host | Windows, Ryzen 7 5700X, 32GB RAM |
| Hypervisor | VirtualBox 7.2.8 |
| Target VM | Windows 10 Enterprise LTSC 21H2 — clean install |
| Attacker account | `analyst01` (standard user) |
| Admin account | `admin` (local administrator) |
| Investigator VM | Kali Linux 2026.1 |
| Network | Host-only (isolated — no internet during attack simulation) |
| External device | Simulated USB via VHD mounted in VirtualBox |

---

## Tools

| Tool | Version | Purpose |
|---|---|---|
| Autopsy | 4.23.1 | Disk analysis, artifact extraction |
| The Sleuth Kit (TSK) | 4.14.0 | CLI filesystem analysis, validation |
| Volatility | 3.x | Memory forensics |
| Wireshark | 4.6.6 | Network traffic (if applicable) |
| ewfacquire / ewfverify | 20140816 | E01 forensic acquisition |
| qemu-img | — | VDI to raw conversion |
| GPG | — | Sealed attacker log encryption |
| sdelete (Sysinternals) | — | Anti-forensic tool used by attacker |

---

## Anti-Forensic Techniques Simulated

- File deletion with `sdelete` (secure overwrite)
- Timestomping via PowerShell
- Attempted Windows Event Log clearing
- File renaming and compression before exfiltration

---

## Methodology

### Phase 00 — Attack Simulation (Attacker perspective)
- Create KYC dataset (customer records)
- Copy files to simulated USB device
- Attempt anti-forensic countermeasures
- Document all actions in sealed GPG-encrypted log
- Acquire memory dump before shutdown
- Take VM snapshot

### Phase 01 — Environment Setup (Investigator perspective)
- VM configuration documentation
- Network isolation verification
- Tool verification

### Phase 02 — Forensic Acquisition
- Memory dump acquisition (pre-shutdown)
- Disk acquisition — E01 format (MD5 + SHA-256)
- Hash verification
- Chain of custody initiated

### Phase 03 — Memory Analysis (Volatility)
- Process list (`pslist`, `pstree`)
- Network connections (`netstat`)
- DLL analysis
- Evidence of anti-forensic tools in memory
- Suspicious artifacts

### Phase 04 — Disk Analysis
- Partition layout
- Deleted file recovery (TSK + Autopsy)
- USN Journal (`$UsnJrnl`) — proof of file existence post-deletion
- Windows Event Logs (Security, System, USB)
  - Event ID 4663 — file access
  - Event ID 4688 — process creation
  - Event ID 6416 — USB device connected
  - Event ID 1102 — Event Log cleared (if attempted)
- Registry artifacts — USB device history, UserAssist, ShellBags
- Browser history — searches related to anti-forensic tools
- Prefetch — anti-forensic tool execution
- NTFS timestamp analysis ($SI vs $FN — timestomping detection)

### Phase 05 — Anti-Forensic Analysis
- Timestomping verification
- sdelete artifact recovery attempts
- Event Log tampering evidence
- What the attacker tried to hide vs. what was recovered

### Phase 06 — Timeline Reconstruction
- Unified timeline: memory + disk + Event Logs
- Attacker action sequence reconstructed

### Phase 07 — Report and Sealed Log Comparison
- Formal forensic report
- Open sealed GPG log
- Compare: attacker actions vs. investigator findings
- Document what was found, what was missed, and why

---

## Key Forensic Artifacts (to be confirmed during investigation)

| Artifact | Expected location | Significance |
|---|---|---|
| KYC files (or remnants) | `C:\Users\analyst01\` or unallocated | Proof of data in possession |
| USB device artifacts | Registry `USBSTOR` hive | Proof of external device connection |
| sdelete execution | Prefetch, Event Log 4688 | Anti-forensic intent |
| USN Journal entries | `$Extend\$UsnJrnl` | Proof files existed post-deletion |
| Timestomping evidence | $SI ≠ $FN comparison | Timestamp manipulation |
| Memory artifacts | Volatility output | Tools/processes active at time of dump |
| Browser history | Edge/Chrome SQLite | Research on anti-forensic techniques |

---

## Sealed Attacker Log

The attacker's actions will be documented in a plaintext file immediately after the attack simulation phase. This file will be encrypted with GPG before the investigation begins and opened only after the forensic report is finalized.

This methodology ensures investigator objectivity and allows the final report to include a blind analysis comparison: what the investigator found vs. what actually happened.

```bash
# Encryption (after attack session)
gpg --symmetric --cipher-algo AES256 attacker-log.txt

# Decryption (after report is finalized)
gpg --decrypt attacker-log.txt.gpg > attacker-log-revealed.txt
```

---

## Deliverables

| File | Description |
|---|---|
| `chain-of-custody.md` | Full evidence handling record |
| `attacker-log-revealed.txt` | Decrypted attacker log (published post-investigation) |
| `phase00-attack-simulation/README.md` | Attack methodology (written post-investigation) |
| `phase01-environment-setup/README.md` | Lab configuration |
| `phase02-forensic-acquisition/README.md` | Acquisition documentation |
| `phase03-memory-analysis/README.md` | Volatility findings |
| `phase04-disk-analysis/README.md` + `findings.md` | Disk artifact analysis |
| `phase05-anti-forensic-analysis/README.md` | Anti-forensic detection |
| `phase06-timeline/README.md` | Unified timeline |
| `phase07-report/README.md` | Report summary |
| `forensic-report-insider-threat.pdf` | Formal forensic report |

---

## Repository Structure (planned)

```
insider-threat-investigation/
├── chain-of-custody.md
├── forensic-report-insider-threat.pdf
├── README.md
├── phase00-attack-simulation/
│   └── README.md
├── phase01-environment-setup/
│   ├── README.md
│   └── screenshots/
├── phase02-forensic-acquisition/
│   ├── README.md
│   └── screenshots/
├── phase03-memory-analysis/
│   ├── README.md
│   ├── findings.md
│   └── screenshots/
├── phase04-disk-analysis/
│   ├── README.md
│   ├── findings.md
│   └── screenshots/
├── phase05-anti-forensic-analysis/
│   ├── README.md
│   ├── findings.md
│   └── screenshots/
├── phase06-timeline/
│   ├── README.md
│   └── forensic-timeline.html
└── phase07-report/
    ├── README.md
    └── forensic-report-insider-threat.pdf
```

---

*Blueprint — ITI-2026-001 — NexChain Exchange Insider Threat Investigation*
