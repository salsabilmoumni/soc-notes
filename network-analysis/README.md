# Network Analysis — Field Notes

Wireshark filters and network forensics tips.

---

## Wireshark filters

### SYN scan detection (no ACK = port scan)
```
tcp.flags.syn == 1 && tcp.flags.ack == 0
```
Locates SYN packets without corresponding ACKs — characteristic of Nmap SYN scans.
Also check: **Statistics → Conversations** for a visual summary of connection attempts.

### TLS — find server certificate public key by session ID
```
tls.handshake.session_id == da4a0000342e4b73459d7360b4bea971cc303ac18d29b99067e46d16cc07f4
```

### TLS 1.3 — find Client Random for a specific domain
```
tls.handshake.type == 1 && tls.handshake.extensions_server_name == "protonmail.com"
```
`handshake.type == 1` = Client Hello. The Client Random is used as a session identifier in TLS 1.3.

---

## Common filter patterns

| Goal | Filter |
|---|---|
| HTTP traffic only | `http` |
| DNS queries | `dns` |
| Traffic to/from specific IP | `ip.addr == 192.168.1.100` |
| Traffic between two hosts | `ip.addr == 1.1.1.1 && ip.addr == 2.2.2.2` |
| Specific TCP port | `tcp.port == 4444` |
| Failed TCP connections | `tcp.flags.reset == 1` |
| HTTP GET requests | `http.request.method == "GET"` |
| HTTP POST requests | `http.request.method == "POST"` |
| Packets containing a string | `frame contains "password"` |
