# Phishing Analysis — Field Notes

Tools and workflow for analyzing phishing emails and malicious attachments.

---

## Analysis tools

| Tool | Use |
|---|---|
| Email Header Analyzer | Parse received headers, trace routing, find sender IP |
| URLHaus | Check if a URL has been reported as malicious |
| URLScan.io | Scan and screenshot a URL safely |
| VirusTotal | Hash, URL, and domain reputation |
| MalwareBazaar | Search for known malware samples by hash |
| oledump.py | Extract streams from MSG and Office files |

---

## Email header analysis tips

- **Sender IP:** Found in the bottom-most `Received` header (closest to origin).
- **Transmission delay:** Compare timestamp in first `Received` header vs last `Received` header.
- **SPF/DKIM/DMARC:** Check `Authentication-Results` header for pass/fail status.

---

## Oledump — phishing email (MSG) analysis

MSG files use **Compound File Binary Format** — oledump extracts their streams.

### Initial triage — list all streams
```powershell
python oledump.py -p plugin_msg.py C:\...\T1598.msg
```

### Summary view with headers
```powershell
python oledump.py -p plugin_msg_summary.py --pluginoptions -H C:\...\T1598.msg
```

### Read message body (find embedded passwords)
```powershell
python oledump.py -p plugin_msg_summary.py --pluginoptions -b C:\...\T1598.msg
```

### Extract a specific stream by index
```powershell
# Stream 38 = body in this example
python oledump.py -p plugin_msg.py C:\...\T1598.msg -s 38 -S

# Export stream 4 as HTML file
python oledump.py -p plugin_msg.py C:\...\T1598.msg -s 4 -d > out.html
```

### Search within stream output
```powershell
python oledump.py -p plugin_msg.py C:\...\T1598.msg | Select-String "Attach long filename"
```

### Plugin reference
```
plugin_msg.py          — general stream inspection
plugin_msg_summary.py  — summary view with header/body options
  --pluginoptions -H   — show email headers
  --pluginoptions -b   — show message body
```

> **Oledump cheat sheet:** [SANS 325.pdf](https://sansorg.egnyte.com/dl/3ydBhha67l)

---

## Common phishing workflow

```
1. Extract and parse email headers → find sender IP, check SPF/DKIM/DMARC
2. Check sender domain → URLScan / VirusTotal
3. Extract URLs from body → URLHaus / VirusTotal
4. If attachment present → hash it → VirusTotal / MalwareBazaar
5. If MSG file → oledump for stream extraction
6. If HTML attachment → check for redirects, obfuscated JS
7. Document: sender IP, domain, URLs, hashes, techniques used
```
