# Endpoint Forensics — Field Notes

Memory forensics with Volatility3, artifact analysis, and DFIR investigation tips.

---

## Volatility3 — Core commands

### List processes with PID dump
```bash
python3 vol.py -f memory.dmp windows.pslist --pid 6988 --dump
```
`--dump` extracts the process executable to disk for hash calculation or further analysis.

### Get SIDs and privileges for a process
```bash
python3 vol.py -f ~/Downloads/CyberDefenders/192-Reveal/192-Reveal.dmp \
  windows.getsid --pid 3692
```
Uncovers associated SIDs, user accounts, and privileges for a given PID.

### Memory region details (VAD info)
```bash
python vol.py -f 'C:\...\MemoryDump.mem' windows.vadinfo --pid 5896
```
Shows memory regions for a process — size, attributes, and protections. Useful for detecting injected code.

### Dump files associated with a process
```bash
python3 vol.py -f ~/Downloads/CyberDefenders/106-RedLine/MemoryDump.mem \
  windows.dumpfiles --pid 5896
```
Extracts files held open by a process. Hash the output and check against VirusTotal.

### UserAssist — track application execution
```bash
python .\vol.py -r pretty -f memory.dmp windows.registry.userassist > userassist.txt
```
The `UserAssist` registry key tracks apps executed via Windows Explorer shell — includes timestamps and active duration. Critical for timeline reconstruction.

### Get MD5 of a process executable
```bash
# Step 1 — dump the process memory
python .\vol.py -f memory.dmp windows.pslist --pid 6988 --dump

# Step 2 — hash the dumped file (PowerShell)
Get-FileHash -Algorithm MD5 .\pid.6988.0x...exe
```

---

## Prefetch files

Parse all prefetch files and export to CSV:
```powershell
PECmd.exe -d C:\Windows\Prefetch --csv "C:\output" --csvf prefetch.csv
```

> **Key use case:** Prefetch files for `JAVA.EXE` reveal which JAR files were executed — includes full path. Useful for finding malicious JAR execution.

---

## AmCache

Records metadata (path, hashes, timestamps) for every executed file — even if the file has been deleted.

```powershell
AmcacheParser.exe -f "D:\[root]\Windows\appcompat\Programs\Amcache.hve" \
  --csv . --csvf amcache.csv
```

> AmCache file location: `Windows\appcompat\Programs\Amcache.hve`

---

## PowerShell history

User command history persists here:
```
C:\Users\<username>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

Look for: `-NoExit` flags, `Set-Location` to unusual paths, encoded commands, `Invoke-Expression`, outbound transfers.

---

## Oledump — MSG and Office analysis

### Initial analysis of MSG file
```powershell
python oledump.py -p plugin_msg.py C:\...\T1598.msg
```

### Search for specific string in streams
```powershell
python oledump.py -p plugin_msg.py C:\...\T1598.msg | Select-String "Attach long filename"
```

### Extract email headers (find sender IP)
```powershell
python oledump.py -p plugin_msg_summary.py --pluginoptions -H C:\...\T1598.msg
```
> **Tip:** To calculate email transmission delay, compare timestamps in the first and last `Received` headers.

### Read message body (find password in body)
```powershell
python oledump.py -p plugin_msg_summary.py --pluginoptions -b C:\...\T1598.msg
```

### Extract a specific stream by index
```powershell
# First find the stream index from initial analysis, then extract it
python oledump.py -p plugin_msg.py C:\...\T1598.msg -s 38 -S

# Export stream to file (e.g. embedded HTML)
python oledump.py -p plugin_msg.py C:\...\T1598.msg -s 4 -d > out.html
```

> MSG files are **Compound File Binary Format** — that's why oledump works on them.

---

## Password cracking

### Hashcat — NTLM hash cracking
```powershell
hashcat.exe -m 1000 -a 0 hash.txt password.txt
```
`-m 1000` = NTLM hash mode.

### Extract password hashes with Mimikatz
```powershell
mimikatz # lsadump::sam /sam:C:\...\SAM /system:C:\...\SYSTEM
```
Requires offline SAM and SYSTEM registry hives.

---

## DNS resolution (PowerShell)
```powershell
Resolve-DnsName -Name 185.70.41.130 -Type A
```
`-Type A` = query for IPv4 address record. Useful for reverse lookups on suspicious IPs found in logs.

---

## Jump Lists

Right-click on a taskbar application icon → shows recent files, common tasks.
Forensically valuable for proving a user opened a specific file via an application.

---

## File wiping vs deletion

| Action | Recoverable? |
|---|---|
| Standard delete | Yes — OS removes reference but data remains on disk |
| File shredding / wiping | No — data overwritten multiple times, unrecoverable |

---

## Key forensic artifacts — quick reference

| Artifact | Location | What it reveals |
|---|---|---|
| Prefetch | `C:\Windows\Prefetch\` | Program execution history |
| AmCache | `Windows\appcompat\Programs\Amcache.hve` | Executed file hashes and paths |
| UserAssist | Registry — NTUSER.DAT | GUI app execution via Explorer |
| PowerShell history | AppData\...\PSReadLine\ | Command history per user |
| Jump Lists | AppData\Roaming\Microsoft\Windows\Recent\ | Recent files per application |
| SAM hive | `Windows\System32\config\SAM` | User accounts and login counts |
| Skype DB | SQLite database in AppData | Conversation history |
| PST files | Outlook data | Email archive — use PSTViewer |
