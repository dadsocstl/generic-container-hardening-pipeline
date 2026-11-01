# Generic Container Hardening Pipeline

Drop into any GitLab repo. Critical/High vulns, restricted licenses, and FOCI denylist matches fail the pipeline.

## Key variables
- `FAIL_ON_CRITICAL` / `FAIL_ON_HIGH` (default true)
- `ENABLE_TRIVY` (default true) — vuln + license scan
- `COSIGN_KEY` or `COSIGN_KEYLESS=true`
- Populate `config/foreign_origin_denylist.txt` for FOCI checks

See full variable list and usage in the previous README content.
