# Splunk Detection — Field Notes

SPL queries built from real investigations. Copy-paste ready with context on what each detects.

---

## Reconnaissance / Initial access

### Discover available log sources
```splunk
| metadata type=sourcetypes | dedup sourcetype | table sourcetype
```

### Find HTTP downloads from Suricata logs
```splunk
sourcetype="suricata" event_type="http"
| stats values(http.http_user_agent) as user_agents,
        values(http.url) as urls,
        values(src_ip) as server
  by dest_ip
```

### Narrow to executable file downloads
```splunk
sourcetype="suricata" event_type="http" AND http.url="*.exe"
| stats values(http.http_user_agent) as user_agents,
        values(http.url) as urls,
        values(src_ip) as server
  by dest_ip
```

---

## Identity & access

### Count failed AWS console logins by user
```splunk
index="aws_cloudtrail" eventSource="signin.amazonaws.com"
errorMessage="Failed authentication"
| stats count by userIdentity.userName
| sort - count
```

---

## Kerberoasting detection (Event ID 4769)

Detects multiple service ticket requests from the same user within 1 second — a hallmark of automated Kerberoasting tools.

```splunk
index="kerberoasted" AND event.code=4769
| bucket span=1s _time
| stats values(winlog.event_data.ServiceName) as Services
        count
        by winlog.event_data.TargetUserName _time
| where count > 1
```

> **Logic:** Time bucketing groups events into 1-second windows. Multiple RC4-encrypted TGS requests in the same second = likely Kerberoasting.

---

## Persistence detection

### New service installation (Event ID 7045)
```splunk
index=* event.code=7045
| table _time, winlog.event_data.ServiceName,
               winlog.event_data.AccountName,
               winlog.event_data.ImagePath
```
Event ID 7045 logs new service creation — attackers install services for persistence, payload execution, and lateral movement.

### Run key persistence (Event ID 13 — Registry value set)
Look for modifications to:
```
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
```

---

## RDP enablement via registry (Event ID 1 — Process creation)

Detect this command being executed:
```powershell
reg add "hklm\system\currentcontrolset\control\terminal server" /f /v fDenyTSConnections /t REG_DWORD /d 0
```

Splunk query (Sysmon Event ID 1):
```splunk
index=* event.code=1
| search CommandLine="*fDenyTSConnections*"
| table _time, host, winlog.event_data.CommandLine, winlog.event_data.User
```

Filter for RDP logins specifically:
```splunk
index=* event.code=4624 winlog.event_data.LogonType=10
| table _time, host, winlog.event_data.TargetUserName,
               winlog.event_data.IpAddress
```

---

## WMI persistence (Sysmon Event IDs 19, 20, 21)

```splunk
index=* (event.code=19 OR event.code=20 OR event.code=21)
| table _time, event.code, winlog.event_data.Name,
               winlog.event_data.Query, winlog.event_data.Consumer
| sort _time
```

All three event IDs together indicate WMI subscription persistence:
- **19** — Filter created (trigger condition defined)
- **20** — Consumer created (payload defined)
- **21** — Filter bound to consumer (persistence armed)

---

## Data exfiltration indicators

PowerShell execution with `-NoExit` flag running from staging directory:
```splunk
index=* event.code=1
| search CommandLine="*-NoExit*" CommandLine="*Set-Location*"
| table _time, winlog.event_data.CommandLine, winlog.event_data.User, host
```

> **Context:** `-NoExit` keeps the session alive after script runs. Combined with `Set-Location C:\Shares`, this suggests files were staged for exfiltration.

---

## Key Windows event IDs — reference

| Event ID | Source | Meaning |
|---|---|---|
| 4624 | Security | Successful logon (check LogonType) |
| 4625 | Security | Failed logon |
| 4769 | Security | Kerberos service ticket requested |
| 7045 | System | New service installed |
| 1 | Sysmon | Process creation |
| 3 | Sysmon | Network connection |
| 11 | Sysmon | File created |
| 13 | Sysmon | Registry value set |
| 19/20/21 | Sysmon | WMI filter/consumer/binding |
| 1102 | Security | Audit log cleared |
| 104 | System | Event log cleared |
