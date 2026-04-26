# Detection Engineering — Field Notes

Using Chainsaw and Sigma rules for log hunting.

---

## Chainsaw

### Search for specific event IDs in historical logs
```powershell
chainsaw.exe search C:\...\Historical -e 1102 -e 104
```
Event IDs `1102` and `104` = audit log clearing and event log clearing — a common attacker anti-forensics step.

### Hunt with a Sigma rule
```powershell
chainsaw.exe hunt C:\...\Historical `
  --sigma C:\...\sigma_rule\event_log_clearing_powershell.yml `
  --mapping C:\...\mappings\sigma-event-logs-all.yml
```

> Chainsaw maps Sigma conditions to Windows event log fields using the mapping file. Use `sigma-event-logs-all.yml` for broad coverage.

---

## Log clearing — what to look for

| Event ID | Log | Meaning |
|---|---|---|
| 1102 | Security | Security audit log cleared |
| 104 | System | System event log cleared |

If these appear near the start of an incident timeline, the attacker attempted to erase evidence. Correlate with events just before the clearing to reconstruct what was deleted.
