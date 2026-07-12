# Phase 05 — Anti-Forensic Analysis

## Objective

Synthesize the findings from Phases 03 (Memory Analysis) and 04 (Disk Analysis) into a focused evaluation of the three anti-forensic techniques used in Phase 00: secure file deletion (SDelete), event log clearing (`wevtutil`), and timestamp manipulation (timestomping). Unlike prior phases, this phase does not introduce new tools or commands — it re-examines evidence already collected, organized around a different question: for each technique, what did the attacker successfully hide, and what gave it away anyway?

This phase directly supports the "what was found vs. what was missed" comparison planned for the final report (Phase 07), once the sealed attacker log is opened.

---

## Technique 1 — Secure File Deletion (SDelete)

**Command used:** `C:\Tools\SDelete\sdelete64.exe -accepteula "C:\Users\analyst01\Documents\kyc_customers.csv"`
**Executed as:** `analyst01` (standard user — no elevation required)
**Attacker's goal:** permanently destroy the original KYC file, including its content, to prevent any recovery from the source location.

### What worked (partial anti-forensic success)

The MFT (Master File Table) yielded **no recoverable trace** of the file — not the content, not even a deleted/orphaned entry recording the file's name. Three separate `fls` searches, with progressively broader scope (recursive, directory-targeted, deleted-inclusive), all returned empty (Phase 04, Step 3). This is a stronger result than a standard deletion would produce; SDelete's overwrite behavior appears to have also invalidated the MFT entry itself, not just the file's data.

### What exposed it anyway

| Source | What it revealed |
|---|---|
| USN Journal | 10 occurrences of `kyc_customers.csv`, proving the file existed and underwent activity — independent of the MFT |
| Prefetch | `SDELETE64.EXE-6548E1FA.pf`, confirming the tool itself ran, with a last-execution timestamp (11:11) |
| ConsoleHost_history (analyst01) | The exact command line used, recovered verbatim from disk |
| Memory strings (Phase 03) | The string `sdelete64.exe`, plus the surrounding command sequence, recovered from RAM prior to shutdown |

**Net result:** SDelete succeeded at its narrowest technical goal (defeating MFT-based content/name recovery) but failed completely at its broader goal (concealing that the deletion happened at all). Four independent artifact types — none of which depend on each other — converge on the same conclusion.

---

## Technique 2 — Security Event Log Clearing (`wevtutil`)

**Command used:** `wevtutil cl Security`
**Executed as:** `admin` (required elevation)
**Attacker's goal:** erase the Security event log's history prior to the attack, removing any audit trail of file access or suspicious activity that might have been logged before the anti-forensic actions began.

### What worked (partial anti-forensic success)

All Security log content generated **before** 2026-07-04 15:20:54 UTC was genuinely destroyed and is unrecoverable from the live `Security.evtx` file — the log's parsed size (1226 lines) is small enough to suggest a near-total reset, and the log's very first surviving event is the clearing action itself.

### What exposed it anyway

| Source | What it revealed |
|---|---|
| Event ID 1102 | Windows' own, automatically-generated record of the log being cleared — user `admin`, timestamp `2026-07-04 15:20:54.560593 UTC`, `ClientProcessId 7812` |
| Prefetch | `WEVTUTIL.EXE-EF5861C4.pf`, confirming execution (last run 11:20) |
| ConsoleHost_history (admin) | The exact command recovered verbatim from the admin profile's history |

**Net result:** this technique carries an inherent, structural flaw — Windows generates Event ID 1102 specifically to record the act of clearing the audit log, and there is no way to suppress that specific event using `wevtutil cl` alone (it would require disabling auditing beforehand, a separate and more detectable action). The attacker successfully destroyed the log's prior contents but could not avoid leaving behind unambiguous proof of *who* cleared it and *when* — arguably a worse outcome for the attacker than leaving the log untouched, since it draws direct attention to the exact moment anti-forensic activity began.

---

## Technique 3 — Timestomping

**Commands used:**
```powershell
$file = Get-Item "E:\kyc_customers.csv"
$file.CreationTime = "01/01/2024 08:00:00"
$file.LastWriteTime = "01/01/2024 08:00:00"
$file.LastAccessTime = "01/01/2024 08:00:00"
```
**Executed as:** `analyst01`
**Attacker's goal:** disguise the true creation date of the file copied to the simulated USB device, making it appear to have existed since January 2024 rather than the actual incident date.

### What worked (partial anti-forensic success)

The `$STANDARD_INFORMATION` ($SI) attribute — the timestamp data exposed to and displayed by Explorer, PowerShell, and virtually every common file-inspection tool — was successfully overwritten with the falsified date. Any investigator relying solely on standard OS-level file properties would see the falsified 2024 date and could reasonably conclude the file predated the incident.

### What exposed it anyway

| Source | What it revealed |
|---|---|
| `$FILE_NAME` ($FN), via `istat` | Retained the real creation timestamp (`2026-07-04 10:50:45`) — this attribute, stored in the parent directory's index, is not exposed to the same easy modification path as $SI and was left untouched |
| `$SI`'s own MFT Modified field | Retained the real time the timestomping action occurred (`2026-07-04 11:26:30`) — this specific sub-field is updated automatically by the file system on any MFT change and was not (and could not be, via this technique) directly overwritten |
| ConsoleHost_history (analyst01) | The exact three-line command sequence, recovered verbatim |

**Net result:** the discrepancy between $SI and $FN is close to definitive, structural proof of tampering — and critically, it does not depend on any log, memory dump, or command history surviving. Even if every other artifact in this investigation had been destroyed, this single structural check on the NTFS metadata would still expose the manipulation.

---

## Anti-Forensic Effectiveness Matrix

| Technique | Attacker's goal | What succeeded | What failed / exposed it |
|---|---|---|---|
| SDelete | Prevent file recovery | MFT-level recovery blocked (content + entry name) | USN Journal, Prefetch, ConsoleHost_history, memory strings |
| `wevtutil cl Security` | Erase audit trail | Prior log content destroyed | Event ID 1102 (self-incriminating by design), Prefetch, ConsoleHost_history |
| Timestomping | Disguise file creation date | $SI (user-facing) successfully falsified | $FN (directory index), $SI's own MFT Modified field, ConsoleHost_history |

**Overall assessment:** all three techniques achieved their narrowest, most literal objective (destroy this specific piece of data, in this specific location) but **none of the three achieved the broader goal of hiding that anti-forensic activity took place at all.** In every case, at least three independent artifact categories — spanning memory, disk metadata, and persistent command history — converged on the same conclusion. This pattern is consistent with tooling (SDelete, `wevtutil`, PowerShell property assignment) designed to alter a single, specific data point rather than comprehensively erase every trace of its own use across the operating system.

---

## Notable Gap: Process-Creation Auditing

One environment-level factor limited how much *additional* corroboration could have been gathered: **Event ID 4688 (process creation) auditing was not enabled** during the Phase 01 environment setup, which is the Windows default configuration. Had it been enabled, the Security event log would likely have captured the creation of the `sdelete64.exe` and `wevtutil.exe` processes directly (for any activity occurring after the 15:20:54 log clear) — providing a fourth, independent confirmation source for at least part of the timeline. This is noted here as a methodology observation for future lab iterations, not as an investigative failure — the absence was documented and explained (Phase 04, Step 6) rather than left unexplained.

---

## Findings Summary

| Item | Result |
|---|---|
| SDelete — file/MFT recovery | ❌ Not recoverable via MFT |
| SDelete — existence/activity proof | ✅ Confirmed via USN Journal, Prefetch, ConsoleHost_history, memory |
| `wevtutil` — log content recovery | ❌ Prior log content destroyed |
| `wevtutil` — execution/actor proof | ✅ Confirmed via Event ID 1102, Prefetch, ConsoleHost_history |
| Timestomping — $SI (user-facing) | ❌ Successfully falsified |
| Timestomping — structural proof ($FN) | ✅ Confirmed via `istat` ($SI vs $FN discrepancy) |
| Overall anti-forensic effectiveness | Partial — data-level goals achieved; concealment of activity itself failed across all three techniques |

---

*Phase 05 — ITI-2026-001 — NexChain Exchange Insider Threat Investigation*

**Next:** [Phase 06 — Timeline Reconstruction](../phase06-timeline/README.md)
