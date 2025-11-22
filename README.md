# Hunting in Memory

This repository contains a detailed forensic analysis of a Windows XP memory image as part of **Lab: Memory Analysis**, completed for **IS-3523: Intrusion Detection and Incident Response** in March 2025.  
The objective was to analyze a captured memory dump, identify active malware, enumerate processes, uncover attacker activity, and document the forensic evidence extracted using the Volatility framework.

---

## Project Overview

The compromised system’s memory (`KobayashiMaru.vmem`) was examined using Volatility to build a full picture of the operating environment and attacker activity. Over the course of the lab, the analyst:

- Identified OS version, SP level, and RAM characteristics using `imageinfo`.
- Enumerated running processes and flagged suspicious executables such as **poisonivy.exe**, **nc.exe**, **bircd.exe**, **iroffer.exe**, and **cryptcat.exe**.
- Listed loaded DLLs for malware correlation.
- Used `netscan` / `connections` plugins to identify open sockets tied to RATs and IRC bots.
- Extracted evidence of active user sessions, including console activity tied to user **Daniel Faraday**.
- Reconstructed attacker behavior by correlating processes, DLLs, and network activity.
- Documented the absence of password hashes due to missing registry hives.

The complete write-up, including screenshots, can be found in **lab_report.md**.

---

## Repository Structure
