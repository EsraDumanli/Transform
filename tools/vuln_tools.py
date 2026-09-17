"""CVE lookups against the public NVD database.

Read-only queries to the National Vulnerability Database's public REST
API. No exploitation, no credential testing — purely "does a known CVE
exist for this product/version".
"""

import time

import requests

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def lookup_cves_for_product(product: str, version: str = "", max_results: int = 5) -> dict:
    """Query the NVD for known CVEs matching a product name (and optional version).

    Use this for each piece of software/firmware discovered by the device
    or network scans (e.g. product="OpenSSH", version="8.1") to see if it
    has publicly known vulnerabilities.
    """
    keyword = f"{product} {version}".strip()
    params = {"keywordSearch": keyword, "resultsPerPage": max_results}
    try:
        resp = requests.get(NVD_API, params=params, timeout=15)
        # Be polite to the public, unauthenticated rate limit (5 req/30s).
        time.sleep(1.5)
        if resp.status_code != 200:
            return {"product": product, "version": version, "error": f"HTTP {resp.status_code}"}
        data = resp.json()
        results = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id")
            descriptions = cve.get("descriptions", [])
            english_desc = next(
                (d["value"] for d in descriptions if d.get("lang") == "en"), None
            )
            metrics = cve.get("metrics", {})
            severity = None
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics and metrics[key]:
                    severity = metrics[key][0]["cvssData"].get("baseSeverity") or metrics[key][0].get("baseSeverity")
                    break
            results.append({"cve_id": cve_id, "severity": severity, "description": english_desc})
        return {
            "product": product,
            "version": version,
            "total_found": data.get("totalResults", len(results)),
            "cves": results,
        }
    except Exception as exc:  # noqa: BLE001
        return {"product": product, "version": version, "error": str(exc)}
