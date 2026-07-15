# Insider Threat Investigation — NexChain Exchange

**A full-cycle digital forensic investigation of suspected KYC data exfiltration and anti-forensic activity on a Windows 10 Enterprise system.**

`Case ITI-2026-001` · `Windows 10 LTSC` · `Volatility 3 · The Sleuth Kit` · `ISO/IEC 27037 · NIST SP 800-86 · RFC 3227 · LGPD` · `Status: Complete`

---

## Overview

A compliance analyst at **NexChain Exchange** (a fictional crypto exchange) is suspected of exfiltrating customer KYC data — names, national identifiers (CPF), and cryptocurrency wallet addresses — to an external device before resigning, then using anti-forensic techniques to cover their tracks.

This project investigates that incident end to end: from generating the evidence under controlled conditions, through forensic acquisition and memory/disk analysis, to a formal forensic report — using real tools and industry-standard methodology. It is a self-initiated academic portfolio project.

What sets it apart from a generic DFIR exercise is a deliberate **blind-analysis design**: the attacker's actions were sealed in a GPG-encrypted log *before* the investigation began, and that log was opened only after every finding was finalized — allowing an honest, auditable measure of how complete the investigation actually was.

The forensic report goes beyond listing findings: it formally classifies each piece of evidence by reliability (**primary / corroborative / circumstantial**), ties every stated limitation to its concrete impact on the conclusions, and contextualizes how the methodology supports **evidentiary admissibility** — reflecting the standard of a professional forensic examination rather than a tool walkthrough.

---

## The forensic timeline at a glance

![Forensic timeline — ITI-2026-001](phase06-timeline/screenshots/forensic-timeline.png)

All nine events were reconstructed from independent evidence layers (memory, disk metadata, event log) and normalized to UTC. The tight anti-forensic cluster between 15:16–15:26 reveals a deliberate, staged clean-up immediately after exfiltration.

---

## Key findings

| # | Finding | How it was proven |
|---|---------|-------------------|
| 1 | **KYC data was exfiltrated** to a mounted virtual disk (drive E:) | PowerShell command history (memory + disk), USN Journal, memory-resident file object |
| 2 | **The "USB device" was a virtual disk**, attached internally via the OS — not physical | Registry: absent from USBSTOR, present in SCSI as `Ven_Msft Virtual_Disk` |
| 3 | **Three anti-forensic techniques used** — secure deletion, log clearing, timestomping — **all detected** | See anti-forensic matrix below |
| 4 | **Actions attributed to specific accounts** (`analyst01` vs `admin`) | Per-user PowerShell histories recovered from disk |
| 5 | **Log clearing self-recorded** despite the attacker's attempt | Event ID 1102 — Windows logs its own audit-log clear, naming the account and time |
| 6 | **Timestomping structurally proven** | NTFS `$SI` vs `$FN` timestamp discrepancy via `istat` |
| 7 | **100% investigative coverage** | Every sealed-log action independently recovered (blind analysis, Phase 07) |

### Anti-forensic effectiveness

| Technique | What the attacker hid | What exposed it anyway |
|-----------|----------------------|------------------------|
| **SDelete** (secure deletion) | Blocked MFT file recovery | USN Journal, Prefetch, command history, memory |
| **wevtutil** (log clearing) | Destroyed prior log content | Event ID 1102 (self-incriminating), Prefetch, command history |
| **Timestomping** | Falsified user-facing `$SI` timestamps | `$FN` retained the real time; command history |

Every technique achieved its narrow data-level goal — yet none concealed *that the activity happened*, because each was caught by three or more independent sources.

---

## Why this project is relevant to crypto / fintech / financial services

This is a DFIR investigation set squarely in the **crypto-exchange and financial-services context**, and it speaks the sector's language throughout:

- **Insider threat & data exfiltration** — the dominant risk model for exchanges, digital banks, and fintechs holding sensitive customer data.
- **KYC data as the crown jewels** — the investigation centers on the exact data category (identity + wallet) that these organizations are obligated to protect.
- **LGPD framing** — the incident is treated as a personal-data breach under Brazil's data-protection law, with the regulatory implications a real exchange would face (risk assessment, potential ANPD and data-subject notification).
- **Compliance-adjacent forensics** — the analysis combines technical DFIR with the compliance/AML perspective, reflecting how insider-risk investigations actually run inside regulated financial institutions.

*Scope note: this project is a host-based DFIR investigation (memory, disk, registry, file system). It does not include on-chain / blockchain transaction analysis — the wallet data functions as the exfiltrated asset within the scenario, not as the subject of chain tracing.*

---

## Methodology

Eight phases, from incident generation to formal report. All analysis performed against read-only, hash-verified evidence.

| Phase | Focus |
|-------|-------|
| [**00 — Environment Setup**](phase00-environment-setup/) | Two-VM lab (Windows target + Kali investigator), clean baseline snapshot |
| [**01 — Attack Simulation**](phase01-attack-simulation/) | Incident generated from the attacker's perspective; actions sealed in a GPG log |
| [**02 — Forensic Acquisition**](phase02-forensic-acquisition/) | Memory dump (pre-shutdown) + E01 disk image, MD5 + SHA-256 verified |
| [**03 — Memory Analysis**](phase03-memory-analysis/) | Volatility 3 — process list, command history recovered from RAM |
| [**04 — Disk Analysis**](phase04-disk-analysis/) | TSK — MFT, USN Journal, Prefetch, Event Log, Registry, NTFS timestamps |
| [**05 — Anti-Forensic Analysis**](phase05-anti-forensic-analysis/) | Effectiveness of each concealment technique vs. what was recovered |
| [**06 — Timeline Reconstruction**](phase06-timeline/) | Unified, UTC-normalized timeline across all evidence sources |
| [**07 — Report & Sealed Log Comparison**](phase07-report/) | Blind-analysis comparison + formal forensic report |

**Standards applied:** ISO/IEC 27037 (acquisition/preservation), 27035 (incident management), 27041 (method assurance), 27042 (analysis/interpretation), 27043 (investigation process); NIST SP 800-86 & 800-61 (forensic/incident handling); RFC 3227 (order of volatility); LGPD (personal-data breach context).

---

## Key deliverables

- **[Forensic Report (PDF)](forensic-report-insider-threat.pdf)** — the formal, self-contained report
- **[Chain of Custody](chain-of-custody.md)** — full evidence-handling record with hashes
- **Per-phase documentation** — methodology, reasoning, and screenshots for each phase above

---

## Lab environment

| Component | Detail |
|-----------|--------|
| Target VM | Windows 10 Enterprise LTSC 21H2 (`NEXCHAIN-WS01`) |
| Investigator VM | Kali Linux 2026.1 |
| Hypervisor | VirtualBox 7.2.8 (isolated host-only network) |
| Key tools | Volatility 3 · The Sleuth Kit 4.14.0 · ewfacquire · qemu-nbd · GPG |
| Evidence | 8.7 GB memory image · 50 GiB E01 disk image (MD5 + SHA-256 verified) |

---

*ITI-2026-001 — NexChain Exchange Insider Threat Investigation. The organization, accounts, and all customer data are fictitious; this is an academic portfolio project conducted in a controlled laboratory.*
