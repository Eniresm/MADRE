import json, csv, sys

# Input & output
infile = "nvdcve-2.0-2020.json"
outfile = "nvdcve-2020.csv"

with open(infile, "r", encoding="utf-8") as f:
    data = json.load(f)

rows = []
for item in data.get("vulnerabilities", []):
    cve = item.get("cve", {})
    cid = cve.get("id", "")
    pub = cve.get("published", "")
    mod = cve.get("lastModified", "")

    # Description (English only)
    desc = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            desc = d.get("value", "")
            break

    # CVSS v3.1 if available
    cvss_score = ""
    cvss_vector = ""
    metrics = cve.get("metrics", {})
    if "cvssMetricV31" in metrics:
        try:
            cvss = metrics["cvssMetricV31"][0]["cvssData"]
            cvss_score = cvss.get("baseScore", "")
            cvss_vector = cvss.get("vectorString", "")
        except:
            pass

    rows.append([cid, pub, mod, cvss_score, cvss_vector, desc])

# Write CSV
with open(outfile, "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow(["CVE_ID","Published","LastModified","CVSSv3_BaseScore","CVSS_Vector","Description"])
    writer.writerows(rows)

print(f"Wrote {len(rows)} CVEs to {outfile}")
