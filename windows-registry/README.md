# Windows Registry Forensics — Field Notes

Key registry paths for DFIR investigations. All paths reference offline hive analysis unless noted.

---

## Quick reference table

| What you need | Hive | Registry path |
|---|---|---|
| OS build number | SOFTWARE | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion` → `CurrentBuild` |
| Computer name | SYSTEM | `HKLM\SYSTEM\ControlSet001\Control\ComputerName\ComputerName` |
| Time zone | SYSTEM | `HKLM\SYSTEM\ControlSet001\Control\TimeZoneInformation` |
| IP address / DHCP info | SYSTEM | `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces` |
| Computer SID | SOFTWARE | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList` |
| Installed apps | SOFTWARE | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths` |
| Chrome version | SOFTWARE | `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall` |
| Startup persistence | SOFTWARE | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` |
| User login count | SAM | SAM hive → navigate to user account entries |
| Chrome autofill (zip code) | File | `AppData\Local\Google\Chrome\User Data\Default\Web Data` |

---

## Hive locations on disk

| Hive | Path |
|---|---|
| SOFTWARE | `Windows\System32\config\SOFTWARE` |
| SYSTEM | `Windows\System32\config\SYSTEM` |
| SAM | `Windows\System32\config\SAM` |
| NTUSER.DAT (per user) | `Users\<username>\NTUSER.DAT` |

---

## Startup persistence — Run key

The most commonly abused persistence location:
```
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
```
Any value here launches the referenced executable on every system startup. Always check this during incident response.

---

## RDP registry modification

Attackers enable RDP via this registry command:
```powershell
reg add "hklm\system\currentcontrolset\control\terminal server" /f /v fDenyTSConnections /t REG_DWORD /d 0
```

| Part | Meaning |
|---|---|
| `fDenyTSConnections` | Controls whether RDP is allowed |
| `/d 0` | Sets value to 0 = RDP **enabled** |
| `/d 1` | Sets value to 1 = RDP **disabled** (default) |
| `/f` | Force — no confirmation prompt |

---

## Windows logon types

| Type | Name | Description |
|---|---|---|
| 2 | Interactive | Direct console login |
| 3 | Network | Accessing shared resources (SMB) |
| 5 | Service | Service account login |
| 10 | Remote Interactive | **RDP / Terminal Services** |

> Filter by **Logon Type 10** to isolate RDP sessions in event logs.

---

## WMI persistence — Sysmon event IDs

| Event ID | Meaning |
|---|---|
| 19 | WMI Event Filter Creation |
| 20 | WMI Event Consumer Creation |
| 21 | WMI Filter-to-Consumer Binding |

All three together = WMI persistence mechanism established.

The `Win32_NTLogEvent` class allows attackers to monitor specific Windows event types and trigger consumers (scripts/executables) when conditions are met — e.g., on reboot or failed login.

---

## Image/disk verification

To verify a disk image hash in FTK: right-click the image file → **Verify Drive/Image** → compare MD5/SHA1 against provided hash.

---

## Notes

- **File shredder software** permanently deletes files by overwriting data multiple times — standard recovery tools cannot restore shredded files.
- Standard deletion only removes the filesystem reference. File contents remain on disk and are recoverable with disk forensics tools.
- DHCP lease time is stored in the same SYSTEM hive path as IP address information (`Tcpip\Parameters\Interfaces`).
