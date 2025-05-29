# Port Scanner with CVE Lookup 🔍🛡️

A multithreaded Python port scanner that performs:
- 🔎 Fast port scanning (with threading)
- 📥 Banner grabbing (service version detection)
- 🛡️ Real-time CVE vulnerability lookup via the NVD API
- 💾 JSON result export
- 🎨 Color-coded output with CVSS scoring

---

## 🚀 Features

- Scan common or custom port ranges
- Grab banners to identify running services
- Automatically search NVD for known CVEs based on service
- Display top 3 CVEs with CVSS score
- Save results to `output.json`
- Fully customizable via CLI

---

## 🛠️ Requirements

Install required packages:

```bash
pip install -r requirements.txt
