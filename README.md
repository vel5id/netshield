# NetShield 🛡️

[![Tests](https://img.shields.io/badge/tests-159%20passed-brightgreen)](https://github.com/vel5id/netshield)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows-lightgrey)](https://github.com/vel5id/netshield)

**VRChat Network Protection Shield** — защита от DDoS/crash-атак с OSINT-профилированием и ML-детекцией.

<p align="center">
  <img src="docs/demo.png" alt="NetShield Demo" width="600">
</p>

---

## 🔍 OSINT Capabilities

NetShield использует методы Open Source Intelligence для профилирования сетевых соединений:

### WHOIS Enrichment
- **ASN Lookup** — Autonomous System Number и описание
- **GeoIP** — Страна и сеть
- **Network CIDR** — Диапазон адресов
- **Abuse Contact** — Email для жалоб

### Threat Intelligence Feeds
| Feed | Source | Description |
|------|--------|-------------|
| **IPsum** | [GitHub](https://github.com/stamparm/ipsum) | Aggregated malicious IPs (level 3+) |
| **EmergingThreats** | [Proofpoint](https://rules.emergingthreats.net) | Compromised IPs |
| **Feodo** | [abuse.ch](https://feodotracker.abuse.ch) | Botnet C2 servers |

### OSINT Report Generation
```python
from netshield.intel import OSINTReport

reporter = OSINTReport(output_dir="./reports")
report = reporter.generate_session_report(profiles)
reporter.save_markdown(report, "session_2024-01-01")
```

**Output includes:**
- Geographic distribution (Country breakdown)
- ASN distribution (Hosting, Proxy detection)
- Top offenders (by traffic, throttle, threat score)
- High-risk IP profiles with full WHOIS data

---

## 🧠 Threat Scoring

Each IP is scored 0-100 based on OSINT data:

| Factor | Points | Source |
|--------|--------|--------|
| High-risk country | +30 | WHOIS GeoIP |
| Extreme speed (>100 MB/s) | +40 | Traffic analysis |
| High throttle ratio (>50%) | +20 | Rate limiting |
| Suspicious ASN (VPS/hosting) | +15 | WHOIS ASN |
| Proxy/VPN/Tor | +15 | WHOIS + feeds |
| Known malicious (IOC feeds) | +25 | Threat intel |

---

## 🎯 MITRE ATT&CK Mapping

Detected behaviors are mapped to MITRE ATT&CK framework:

| Technique | Name | Detection |
|-----------|------|-----------|
| T1498.001 | Direct Network Flood | Speed > 100 MB/s |
| T1498 | Network DoS | Throttle ratio > 50% |
| T1090.003 | Multi-hop Proxy (Tor) | ASN contains "tor", "exit" |
| T1090 | Proxy | VPN/bulletproof keywords |

---

## Features

- 🔥 **Rate Limiting** — Token Bucket с DROP strategy (без блокировки)
- 🧠 **ML Anomaly Detection** — Isolation Forest + rule fallback
- 📡 **Protocol Tracking** — Раздельная статистика UDP/TCP
- 📝 **HMAC Logging** — Целостность логов

---

## Requirements

- Windows 10/11
- Python 3.10+
- **Administrator privileges**
- WinDivert driver (auto-installed)

## Installation

```powershell
git clone https://github.com/vel5id/netshield.git
cd netshield

# Core dependencies
pip install pydivert ipwhois pyyaml

# Optional: ML + Feeds
pip install scikit-learn numpy httpx
```

## Quick Start

```powershell
# Right-click -> Run as Administrator
.\run.bat
```

### Options
```
--mode      | -m   : vrchat, universal, custom (default: vrchat)
--limit     | -l   : Bandwidth limit MB/s (default: 50)
--burst     | -b   : Burst size MB (default: 10)
--log-dir          : Log directory (default: ./logs)
```

---

## Output Example

```
[OK]  25.00/50 MB/s [████████░░░░░░░░] | UDP:1234(50) TCP:100 | ↓50 | IPs:5
```

### Session Summary
```
PROTOCOL BREAKDOWN:
  UDP:    15234 pkts |   8521 dropped (55.9%)
  TCP:      842 pkts |      0 dropped (0.0%)

⚠ TOP OFFENDERS:
  • [UDP] 185.x.x.x [RU] Score:85 - Bulletproof Hosting Ltd
```

---

## Log Files

| File | Format | Content |
|------|--------|---------|
| `events.jsonl` | JSON Lines | Threat events |
| `traffic.csv` | CSV | All traffic entries |
| `watchlist.json` | JSON | High-score IPs |
| `session_*.md` | Markdown | OSINT report |

---

## Tests

```powershell
pip install pytest pytest-mock
pytest tests/ -v
# 159+ passed
```

## License

MIT
