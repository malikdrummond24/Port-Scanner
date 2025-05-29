import requests
import re

API_KEY = "69b171b2-2365-453e-9b05-b41dbd512e5c"  

def extract_product(banner):
    match = re.search(r'(OpenSSH|Apache|nginx|vsftpd|Microsoft-IIS|MySQL|PostgreSQL)', banner, re.IGNORECASE)
    return match.group(1) if match else banner.split()[0]

def lookup_cves(banner):
    if not banner or banner == "No banner":
        return []

    product = extract_product(banner)
    print(f"[*] Looking up CVEs for: {product}")

    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {
        "apiKey": API_KEY
    }
    params = {
        "keywordSearch": product,
        "resultsPerPage": 3
    }

    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        if response.status_code != 200:
            print(f"[!] Failed to fetch CVEs (HTTP {response.status_code})")
            return []

        data = response.json()
        vulnerabilities = data.get("vulnerabilities", [])
        results = []

        for item in vulnerabilities:
            cve_id = item["cve"]["id"]
            description = item["cve"]["descriptions"][0]["value"]
            cvss_score = "N/A"

            
            metrics = item["cve"].get("metrics", {})
            if "cvssMetricV31" in metrics:
                cvss_score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
            elif "cvssMetricV30" in metrics:
                cvss_score = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
            elif "cvssMetricV2" in metrics:
                cvss_score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]

            results.append((cve_id, f"{description} (CVSS {cvss_score})"))

        return results

    except Exception as e:
        print(f"[!] Error during CVE lookup: {e}")
        return []
