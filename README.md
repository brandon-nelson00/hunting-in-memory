# Hunting in Memory

## Overview

This repository contains a forensic analysis of a memory image captured from a compromised Windows XP system. By leveraging the Volatility framework and other memory forensic tools, the investigation identifies the operating system version, installed RAM, active processes, and user sessions to uncover evidence of malware and unauthorized access.

## Objectives

- Determine the OS and memory characteristics of the system.
- Enumerate running processes and highlight suspicious executables (e.g., poisonivy.exe, nc.exe, bircd.exe, iroffer.exe, cryptcat.exe).
- Identify loaded DLLs and network connections.
- Discover user accounts and console sessions.
- Correlate artifacts to build an attack timeline and identify persistence mechanisms.

## Repository structure

- `README.md` – this file; summarizes the project and provides quick usage tips.
- `lab_report.md` – detailed write-up documenting methodology, analysis steps, results, and conclusions.
- `images/` – directory for screenshots referenced in the report (if applicable).

## Usage

This repository is intended as a reference for memory forensics and incident response education. To reproduce the analysis:

1. Download the memory image (`KobayashiMaru.vmem`) and Volatility.
2. Run `volatility -f KobayashiMaru.vmem imageinfo` to determine OS profile and memory offsets.
3. Use `volatility --profile=WinXPSP2x86 pslist` to list processes, `filescan` to locate hidden files, `consoles` to identify user sessions, etc.
4. Refer to `lab_report.md` for detailed command examples and analysis.

## Key findings

- The memory image corresponds to Windows XP SP2/SP3 with 512 MB of RAM【131694685109100†L37-L61】.
- Suspicious processes such as `poisonivy.exe` (remote access Trojan), `nc.exe` (Netcat), `bircd.exe` (IRC bot), `iroffer.exe` (file sharing bot), and `cryptcat.exe` (encrypted Netcat) were found running【131694685109100†L64-L100】.
- Analysis of the consoles plugin revealed user `Daniel Faraday` as the primary account, with evidence of remote console usage; however, password hashes could not be recovered due to missing hives【131694685109100†L106-L129】.
- These findings indicate that the system was part of an IRC-based botnet controlled through the Poison Ivy RAT and Netcat backdoors.

## References

- [Volatility Framework Documentation](https://www.volatilityfoundation.org/)
- See `lab_report.md` for detailed analysis and citations.
