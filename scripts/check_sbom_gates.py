#!/usr/bin/env python3
"""SBOM / License / FOCI gate. Fails on Critical/High vulns, restricted licenses, or FOCI denylist matches."""
import argparse, json, os, sys
RESTRICTED_LICENSES = {"GPL-2.0", "GPL-2.0-only", "GPL-2.0-or-later", "GPL-3.0", "GPL-3.0-only", "GPL-3.0-or-later", "AGPL-3.0", "AGPL-3.0-only", "AGPL-3.0-or-later", "SSPL-1.0"}
def load_denylist(path):
    if not path or not os.path.isfile(path): return set()
    return {line.strip().lower() for line in open(path) if line.strip() and not line.startswith("#")}
def check_licenses(sbom):
    findings = []
    for pkg in sbom.get("packages", []):
        name = pkg.get("name", "")
        for field in ("licenseConcluded", "licenseDeclared"):
            val = str(pkg.get(field, ""))
            for bad in RESTRICTED_LICENSES:
                if bad.lower() in val.lower():
                    findings.append(f"Restricted license {bad} on package {name}")
    return findings
def check_foci(sbom, denylist):
    findings = []
    for pkg in sbom.get("packages", []):
        name = (pkg.get("name") or "").lower()
        purl = ""
        for ext in pkg.get("externalRefs", []):
            if ext.get("referenceType") == "purl":
                purl = (ext.get("referenceLocator") or "").lower()
        for entry in denylist:
            if entry in name or entry in purl:
                findings.append(f"FOCI match: {name} / {purl} matched '{entry}'")
    return findings
def check_trivy_vulns(trivy_path, fail_crit, fail_high):
    findings = []
    if not trivy_path or not os.path.isfile(trivy_path): return findings
    data = json.load(open(trivy_path))
    for result in data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            sev = (vuln.get("Severity") or "").upper()
            if sev == "CRITICAL" and fail_crit: findings.append(f"CRITICAL {vuln.get('VulnerabilityID')} in {vuln.get('PkgName')}")
            elif sev == "HIGH" and fail_high: findings.append(f"HIGH {vuln.get('VulnerabilityID')} in {vuln.get('PkgName')}")
    return findings
def main():
    p = argparse.ArgumentParser()
    p.add_argument("--sbom", required=True)
    p.add_argument("--trivy", default="")
    p.add_argument("--denylist", default="config/foreign_origin_denylist.txt")
    args = p.parse_args()
    fail_crit = os.environ.get("FAIL_ON_CRITICAL", "true").lower() == "true"
    fail_high = os.environ.get("FAIL_ON_HIGH", "true").lower() == "true"
    sbom = json.load(open(args.sbom))
    denylist = load_denylist(args.denylist)
    findings = check_licenses(sbom) + check_foci(sbom, denylist) + check_trivy_vulns(args.trivy, fail_crit, fail_high)
    if findings:
        print("GATE FAILED:")
        for f in findings: print(f"  - {f}")
        sys.exit(1)
    print("SBOM/license/FOCI gates PASSED")
if __name__ == "__main__": main()
