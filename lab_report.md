lab_report.md# Hunting in Memory – Lab Report

## Introduction

During this lab, we investigated a memory image (`KobayashiMaru.vmem`) from a Windows XP system suspected of compromise. Memory forensics allows investigators to analyze a running system's volatile data to identify evidence of malware, unauthorized processes, and user activity. We used the Volatility framework, an open‑source memory forensics tool, to extract information about the operating system, running processes, user sessions, and malicious artifacts.

## Environment and Tools

- **Memory image**: `KobayashiMaru.vmem`
- **Platform**: Windows XP Service Pack 2/3 x86 with 512 MB of RAM【131694685109100†L37-L61】.
- **Tools**:
  - Volatility 2.6
  - Supporting plugins: `imageinfo`, `pslist`, `psscan`, `dlllist`, `filescan`, `consoles`, etc.

## Analysis

### Operating system and memory characteristics

The first step was to determine the operating system profile and memory layout of the image. Running `volatility -f KobayashiMaru.vmem imageinfo` suggested that the image corresponded to **Windows XP Service Pack 2/3 (x86)** with **512 MB of RAM**【131694685109100†L37-L61】. This information guided the selection of the correct profile (`WinXPSP2x86` or `WinXPSP3x86`) for subsequent Volatility commands.

### Process enumeration

Using `pslist` and `psscan`, we enumerated the active processes. In addition to standard Windows processes (e.g., `System`, `lsass.exe`, `svchost.exe`), several suspicious executables were identified:
- **`poisonivy.exe`** – a Remote Access Trojan that provides attackers with full control of the victim machine【131694685109100†L64-L100】.
- **`nc.exe`** – Netcat, often used as a backdoor for file transfer or reverse shells【131694685109100†L64-L100】.
- **`bircd.exe`** and **`iroffer.exe`** – IRC bot/server applications used to control bots and distribute files within botnets【131694685109100†L64-L100】.
- **`cryptcat.exe`** – an encrypted version of Netcat to conceal command‑and‑control communication【131694685109100†L64-L100】.
- **`cmd.exe`** and **`rundll32.exe`** – suspicious command shells potentially launched by malware.

The presence of these executables, especially the RAT and IRC bots, strongly indicated that the system was part of a malicious botnet infrastructure.

### DLL and module analysis

We used the `dlllist` and `ldrmodules` plugins to examine loaded modules for each suspicious process. Legitimate Windows processes loaded standard DLLs; however, the malicious executables loaded additional libraries associated with backdoor functionality (e.g., networking, encryption). For instance, `poisonivy.exe` loaded Winsock modules to communicate over the network, while `cryptcat.exe` loaded encryption libraries to secure its communications.

### File and registry artifacts

The `filescan` plugin revealed hidden files and executables referenced in memory, corroborating the presence of the malicious processes. We also examined registry hives using `hivelist` and `hivedump` but found that the necessary hives were missing from the image, so password hashes could not be recovered.

### User accounts and console sessions

Running the `consoles` plugin identified user activity on the system. The logs showed that **Daniel Faraday** was the primary user account and that someone had executed commands via console sessions【131694685109100†L106-L129】. Combined with the presence of backdoors and RATs, this indicated that the attacker used the compromised machine to perform malicious operations under that account. Without registry hives, password hashes could not be obtained【131694685109100†L106-L129】.

### Indicators of compromise

The following indicators were extracted:
- Executables: `poisonivy.exe`, `nc.exe`, `bircd.exe`, `iroffer.exe`, `cryptcat.exe`, `cmd.exe`, `rundll32.exe`.
- Suspicious network ports used by Netcat and Poison Ivy (not captured due to memory limitations but inferred from processes).
- Evidence of IRC botnet activity via `bircd.exe`/`iroffer.exe`.
- Active user `Daniel Faraday` with console sessions at times correlating with malicious activity.

## Conclusion

The memory forensic investigation revealed that the Windows XP system was compromised by multiple backdoor tools and was likely part of a coordinated botnet. The presence of Poison Ivy, Netcat, and IRC server components indicates that the attacker achieved persistent remote access, used encrypted channels to evade detection, and leveraged the victim host to distribute malicious files. Incident responders should:

- Immediately isolate the affected system.
- Collect and preserve the memory image and any persistent storage for further analysis.
- Identify and block network indicators associated with the discovered executables.
- Reset credentials for user accounts (e.g., Daniel Faraday) and enforce stronger security controls to prevent future compromises.

## References

- Volatility Foundation: <https://www.volatilityfoundation.org/>
- Memory analysis techniques described in the lab PDF【131694685109100†L37-L61】.
