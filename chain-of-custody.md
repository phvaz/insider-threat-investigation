# Chain of Custody — ITI-2026-001

## Case Information

| Field | Value |
|---|---|
| Case reference | ITI-2026-001 |
| Case name | NexChain Exchange — Insider Threat Investigation |
| Examiner | Paulo Vaz |
| Investigation environment | Isolated host-only lab (VirtualBox 7.2.8), no internet access during attack simulation |
| Target system | Windows 10 Enterprise LTSC 21H2 — `NEXCHAIN-WS01` (`windows-10-dfir-target`) |
| Investigator system | Kali Linux 2026.1 |

This case involved only a single examiner throughout, working within an isolated local lab environment. No third party had access to the target VM, the investigator VM, or any evidence file at any point.

> **Standards note.** This chain of custody is maintained in accordance with **ISO/IEC 27037** (identification, collection, acquisition and preservation of digital evidence) and **NIST SP 800-86** (integrating forensic techniques into incident response). The acquisition order — volatile memory captured before the disk, and before shutdown — follows the **order of volatility** defined in **RFC 3227** (Guidelines for Evidence Collection and Archiving). All evidence integrity is established and re-verifiable through the MD5 and SHA-256 hashes recorded below.

---

## Evidence Items

### Item 1 — Memory Dump (`memdump.elf`)

| Field | Value |
|---|---|
| Description | Full RAM capture of `windows-10-dfir-target`, taken immediately after attack simulation, before VM shutdown |
| Acquisition tool | `VBoxManage debugvm ... dumpvmcore` |
| Acquisition date/time | 2026-07-06 13:21 (host time) |
| Acquired by | Paulo Vaz, from host (outside target VM) |
| File size | 8,730,336,996 bytes (~8.7 GiB) |
| Original location | `C:\Tools\memdump.elf` (host) |
| MD5 | *(not separately calculated — see note below)* |
| SHA-256 | `9e2a212c3a63e484cde27151467fcaa75b9a13aaf3945707b8c8bca2ce14a90e` |
| Hash calculated on | Kali investigator VM, via shared folder `tools-evidence` (read-only) |
| Hash calculated at | 2026-07-06 (Phase 02 wrap-up) |
| Reference | [Phase 01 — Attack Simulation](phase01-attack-simulation/README.md), Step 5 |

### Item 2 — Disk Image (`NEXCHAIN-WS01-DISK01.E01`)

| Field | Value |
|---|---|
| Description | Full disk image of `windows-10-dfir-target`, state at `post-attack` VirtualBox snapshot |
| Source | Consolidated clone of differential snapshot chain (base → `clean-install` → `post-attack`), via `VBoxManage clonemedium` |
| Acquisition tool | `ewfacquire` 20140816, EnCase 6 (.E01) format, deflate/none compression |
| Acquisition method | Direct block-device read via `qemu-nbd` (`/dev/nbd0`, read-only) |
| Acquisition date/time | 2026-07-06, completed 13:05:50 |
| Acquired by | Paulo Vaz, on Kali investigator VM |
| Total size | 53,687,091,200 bytes (50 GiB) |
| Acquisition destination | Dedicated local disk `/mnt/evidence-storage` (60 GiB VDI attached to Kali via SATA) |
| MD5 (from `ewfacquire`) | `7e5404e298b1d886534a2845e4d880bc` |
| MD5 (from `ewfverify`, independent recalculation) | `7e5404e298b1d886534a2845e4d880bc` — ✅ match |
| SHA-256 | `3d61d7774ca4f85a88077d46ce535debe463f341aff2404cc885dc3471886188` |
| Verification tool | `ewfverify` 20140816 |
| Verification date/time | 2026-07-06, completed 13:23:42 |
| Reference | [Phase 02 — Forensic Acquisition](phase02-forensic-acquisition/README.md) |

---

## Custody Timeline

| Timestamp | Event | Actor |
|---|---|---|
| 2026-07-04 11:45 | Simulated removable device (VHD) created and mounted inside target VM | Paulo Vaz (as `analyst01`) |
| 2026-07-04 12:06 | KYC dataset created and copied to simulated external device | Paulo Vaz (as `analyst01`) |
| 2026-07-04 12:16 | SDelete executed against original file (anti-forensic action, attacker perspective) | Paulo Vaz (as `analyst01`) |
| 2026-07-04 12:21 | `wevtutil cl Security` executed (anti-forensic action, attacker perspective) | Paulo Vaz (as `admin`) |
| 2026-07-04 12:33 | Timestomping applied to exfiltrated file | Paulo Vaz (as `analyst01`) |
| 2026-07-04 ~12:40 | Attacker actions log sealed with GPG (AES256); plaintext original deleted | Paulo Vaz (host) |
| 2026-07-06 13:21 | Memory dump acquired from host, VM still running | Paulo Vaz (host) |
| 2026-07-06 ~13:22 | Snapshot `post-attack` taken; VM powered off | Paulo Vaz (host) |
| 2026-07-06 (Phase 02) | Snapshot chain consolidated via `VBoxManage clonemedium` | Paulo Vaz (host) |
| 2026-07-06 (Phase 02) | Consolidated VDI connected read-only via `qemu-nbd` on Kali investigator VM | Paulo Vaz (Kali) |
| 2026-07-06 13:05:50 | Disk image acquired (E01), MD5 hash generated | Paulo Vaz (Kali) |
| 2026-07-06 13:23:42 | Disk image integrity verified (`ewfverify`), MD5 match confirmed | Paulo Vaz (Kali) |
| 2026-07-06 (Phase 02 wrap-up) | SHA-256 calculated for both memory dump and disk image | Paulo Vaz (Kali) |

---

## Storage and Access

| Evidence item | Current storage location | Access control |
|---|---|---|
| `memdump.elf` | Host: `C:\Tools\memdump.elf` | Local host filesystem; accessed read-only by Kali via shared folder for hashing |
| `NEXCHAIN-WS01-DISK01.E01` | Kali investigator VM: `/mnt/evidence-storage/` (dedicated local disk) | Local to Kali VM; not exposed via network shared folder |
| Sealed attacker log (`attacker-log.txt.gpg`) | Host: Desktop | GPG-encrypted (AES256); to be opened only in Phase 07 for blind-analysis comparison |
| Consolidated source clone (`post-attack-consolidated.vdi`) | Host, accessed read-only by Kali via shared folder `iti-2026-001` | Read-only mount — protects original snapshot chain from modification |

---

## Notes

- The memory dump (`memdump.elf`) had only SHA-256 calculated independently; no MD5 was generated for it at acquisition time (`VBoxManage debugvm` does not compute a hash automatically). This is noted here as a minor procedural gap — for future phases, memory dumps should have both hashes generated immediately after acquisition, before any further handling.
- Two disk acquisition attempts failed mid-write due to I/O instability in the VirtualBox shared folder (`vboxsf`) used as the initial output destination. This is documented in detail in [Phase 02](phase02-forensic-acquisition/README.md), Step 3. No evidence was lost or corrupted as a result — the failed partial files were discarded before the successful acquisition began.
- All hash values in this document were independently verified by the examiner and cross-checked against tool output shown in the corresponding phase screenshots.

---

*Chain of Custody — ITI-2026-001 — NexChain Exchange Insider Threat Investigation*
