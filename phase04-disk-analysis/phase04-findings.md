# Phase 04 — Disk Analysis — Findings

Structured summary of evidentiary findings from disk image analysis. For full methodology, investigative reasoning, and troubleshooting narrative, see [README.md](README.md).

---

## Finding 1 — Original File Not Recoverable via MFT

**Artifact:** Master File Table (MFT), via `fls`
**Result:** No entry — active, deleted, or orphaned — found for `kyc_customers.csv` anywhere on the main NTFS partition.
**Interpretation:** SDelete's secure-delete behavior removed or overwrote the MFT entry itself, not just file content. Stronger anti-forensic effect than a standard deletion (Recycle Bin / Shift+Delete), which typically leaves a recoverable MFT entry.

---

## Finding 2 — File Existence Proven via USN Journal

**Artifact:** `$Extend\$UsnJrnl:$J` (inode 42887-128-3), extracted and searched via UTF-16LE string matching
**Result:** 10 occurrences of `kyc_customers.csv` found.
**Interpretation:** Independently proves the file existed and underwent file-system activity (create/write/delete cycle), despite zero MFT-level recoverability. USN Journal and MFT are separate NTFS subsystems — this closed the evidentiary gap left by Finding 1.

---

## Finding 3 — Tool Execution Confirmed via Prefetch

**Artifact:** `C:\Windows\Prefetch\`
**Result:**
- `SDELETE64.EXE-6548E1FA.pf` — last run 2026-07-04 11:11
- `WEVTUTIL.EXE-EF5861C4.pf` — last run 2026-07-04 11:20

**Interpretation:** Independent confirmation of both anti-forensic tools' execution, sourced entirely from disk (no dependency on memory or logs).

---

## Finding 4 — Security Log Clearing Recorded (Event ID 1102)

**Artifact:** `Security.evtx`, Event ID 1102
**Result:**
| Field | Value |
|---|---|
| User | `admin` |
| Timestamp | 2026-07-04 15:20:54.560593 UTC |
| ClientProcessId | 7812 |
| Position in log | First (only) event of significance — log was reset at this point |

**Interpretation:** Windows automatically and unavoidably logs the clearing of its own audit log. This event cannot be suppressed by `wevtutil cl` itself — it would require disabling auditing beforehand. Directly attributes the log-clearing action to the `admin` account at a precise timestamp.

**Related negative finding:** Event ID 4688 (process creation) referencing SDelete was searched for and not found — expected, since process-creation auditing is not enabled by default and was not configured in Phase 01.

---

## Finding 5 — Simulated USB Device Was a Virtual Disk, Not Physical/Passthrough USB

**Artifacts:** Registry (`SYSTEM` hive) — `USBSTOR`, `MountedDevices`, `SCSI`

| Key | Result |
|---|---|
| `ControlSet001\Enum\USBSTOR` | Key does not exist |
| `MountedDevices` | `\DosDevices\E:` present, disk-signature format (not SCSI/CD-ROM path format) |
| `ControlSet001\Enum\SCSI` | `Disk&Ven_Msft&Prod_Virtual_Disk` present (vendor: Microsoft) — distinct from `Disk&Ven_VBOX&Prod_HARDDISK` (the VM's real disk, vendor: VirtualBox) |

**Interpretation:** Combined absence in USBSTOR and presence in SCSI under a Microsoft (not VirtualBox) vendor string conclusively identifies the device as a VHD attached internally via the Windows Virtual Disk Service (`diskpart create vdisk` / `attach vdisk`), not a physical or passed-through USB device.

---

## Finding 6 — GUI Usage Pattern (UserAssist / ShellBags)

**Artifact:** `NTUSER.DAT` (analyst01) — `UserAssist`, `ShellBags`

| Key | Result |
|---|---|
| UserAssist (Count) | `powershell.exe`, `cmd.exe`, `SnippingTool.exe`, `mspaint.exe` present |
| UserAssist (Count) | `sdelete64.exe`, `wevtutil.exe` **absent** |
| ShellBags (BagMRU / Bags) | Both present but **empty** |

**Interpretation:** The attacker launched PowerShell via the Explorer shell (Start Menu), consistent with UserAssist tracking shell-launched programs only. SDelete and wevtutil were invoked *inside* that already-open PowerShell session, so they never passed through the shell layer UserAssist monitors — their absence is expected, not a gap. The empty ShellBags confirms no visual folder browsing (File Explorer) occurred at any point — 100% of navigation was command-line driven (`Get-ChildItem`, `Copy-Item`, etc.).

---

## Finding 7 — Full Command History Recovered from Disk (ConsoleHost_history.txt)

**Artifact:** `PSReadLine\ConsoleHost_history.txt`, per user profile

**analyst01** (`C:\Users\analyst01\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`):
```
net user analyst01 1234
New-Item -ItemType Directory -Path "C:\Tools" -Force
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/SDelete.zip" -OutFile "C:\Tools\SDelete.zip"
Expand-Archive -Path "C:\Tools\SDelete.zip" -DestinationPath "C:\Tools\SDelete"
Get-ChildItem C:\Tools\SDelete\
[... two CSV-creation attempts, one failed on syntax ...]
Copy-Item -Path "C:\Users\analyst01\Documents\kyc_customers.csv" -Destination "E:\kyc_customers.csv"
Get-ChildItem E:\
C:\Tools\SDelete\sdelete64.exe -accepteula "C:\Users\analyst01\Documents\kyc_customers.csv"
Get-ChildItem C:\Users\analyst01\Documents\
$file = Get-Item "E:\kyc_customers.csv"
$file.CreationTime = "01/01/2024 08:00:00"
$file.LastWriteTime = "01/01/2024 08:00:00"
$file.LastAccessTime = "01/01/2024 08:00:00"
Get-Item "E:\kyc_customers.csv" | Select-Object CreationTime, LastWriteTime, LastAccessTime
```

**admin** (`C:\Users\admin\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`):
```
diskpart
wevtutil cl Security
```

**Interpretation:** Complete, unmediated, first-party record of every command typed in both accounts used during the attack. Persistent (survives reboot), unlike the memory-based reconstruction in Phase 03. Allows precise attribution of each action to the correct user account. Considered the single strongest artifact recovered in this phase, and the primary comparison baseline for the Phase 07 blind-analysis review.

---

## Finding 8 — Timestomping Confirmed at the NTFS Structural Level ($SI vs $FN)

**Artifact:** `pendrive.vhd` → MFT entry 38 (`kyc_customers.csv`), via `istat`

| Timestamp | $STANDARD_INFORMATION (displayed) | $FILE_NAME (actual) |
|---|---|---|
| Created | 2024-01-01 06:00:00 (falsified) | 2026-07-04 10:50:45 (real) |
| Modified | 2024-01-01 06:00:00 (falsified) | 2026-07-04 10:50:45 (real) |
| Accessed | 2024-01-01 06:00:00 (falsified) | 2026-07-04 10:50:45 (real) |
| MFT Modified ($SI only) | 2026-07-04 11:26:30 — **not falsifiable via the technique used** | — |

**Interpretation:** Textbook timestomping signature — a discrepancy between $SI (easily altered via common OS APIs) and $FN (stored in the parent directory index, not exposed to the same modification path) is close to definitive, structural proof of timestamp tampering. This evidence exists independent of any log, memory, or history artifact — it would remain detectable even if every other artifact in this investigation had been destroyed. The surviving `MFT Modified` field in $SI additionally corroborates the real time of the timestomping action itself.

---

## Cross-Reference: Actions Attributed by Account

| Action | Account | Evidence source(s) |
|---|---|---|
| VHD creation (diskpart) | admin | ConsoleHost_history (admin) |
| SDelete download/setup | analyst01 | ConsoleHost_history (analyst01) |
| KYC file creation | analyst01 | ConsoleHost_history (analyst01) |
| File copy to E:\ | analyst01 | ConsoleHost_history (analyst01), USN Journal |
| SDelete execution | analyst01 | ConsoleHost_history (analyst01), Prefetch |
| Timestomping | analyst01 | ConsoleHost_history (analyst01), $SI vs $FN |
| Security log clear (`wevtutil`) | admin | ConsoleHost_history (admin), Event ID 1102, Prefetch |

---

*Phase 04 — ITI-2026-001 — NexChain Exchange Insider Threat Investigation*
