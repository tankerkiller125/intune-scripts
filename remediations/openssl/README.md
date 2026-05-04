# Intune OpenSSL Remediation Pair

This folder contains an Intune Proactive Remediation script pair:

- `OpenSSL-Detect.ps1` (Detection)
- `OpenSSL-Remediate.ps1` (Remediation)

## What it does

1. Scans scoped C: locations only: `C:\Users`, `C:\Program Files`, `C:\Program Files (x86)`, `C:\ProgramData`.
2. Finds OpenSSL DLL names (`libcrypto*.dll`, `libssl*.dll`, legacy names), detects binary architecture (`x86`, `x64`, `arm64`), extracts versions, and computes SHA256.
3. Writes detection inventory to `C:\ProgramData\IntuneOpenSSLRemediation\openssl-dll-inventory.json`.
4. Pulls available Windows OpenSSL ZIP versions from an OpenSSL wiki-listed source (`https://www.firedaemon.com/get-openssl`).
5. Remediation reads the inventory file (no re-scan), downloads ZIP, extracts DLLs, and replaces outdated DLLs in-place (with `.bak` backup).

Version parsing rule implemented:

- For OpenSSL versions starting with `1`, branch matching remains on major `1` so legacy builds map to 1.1.1 package sources.
- Trailing letter still acts as patch level ordering (`1.0.2d` < `1.0.2f`, etc.).
- Legacy sub-branch values are preserved in metadata (`LegacyMajor`, `LegacyMinor`) for diagnostics.
- ARM64 handling: OpenSSL `1.x` is treated as unsupported for ARM64 replacement (no ARM64 package branch for 1.x).

## Intune configuration

- Run scripts using the logged-on credentials: **No**
- Enforce script signature check: per tenant policy
- Run script in 64-bit PowerShell: **Yes**

Detection return codes:

- `0`: Compliant
- `1`: Non-compliant / remediation required

Remediation return codes:

- `0`: Success (or no-op)
- `1`: Failure

## Verbose debugging mode

Both scripts support a verbose switch for troubleshooting:

- Detection: `OpenSSL-Detect.ps1 -VerboseMode`
- Remediation: `OpenSSL-Remediate.ps1 -VerboseMode`
- Remediation dry run: `OpenSSL-Remediate.ps1 -DryRun -VerboseMode`
- Remediation with backups: `OpenSSL-Remediate.ps1 -WithBackup -VerboseMode`
- Roll back from backups: `OpenSSL-Remediate.ps1 -RestoreBackup -VerboseMode`

Verbose output includes scanned roots, candidate counts, inventory file actions,
package discovery/download/extraction steps, and replacement actions.

`-DryRun` on remediation performs no changes and reports what downloads,
extractions, and DLL replacements would be executed.

`-WithBackup` makes remediation create `<dll>.bak` before each replacement.

`-RestoreBackup` restores DLLs from existing `<dll>.bak` files listed in the
inventory and exits after restore flow.

Notes:

- `-WithBackup` and `-RestoreBackup` are mutually exclusive.
- `-DryRun` can be combined with `-RestoreBackup` to preview rollback actions.

## Important operational notes

- `OpenSSL-Remediate.ps1` does not run installers. It uses `Expand-Archive` to extract DLLs directly from ZIP packages.
- ZIP replacement DLL selection is constrained to `<arch>\bin\*.dll` paths (`x86\bin`, `x64\bin`, `arm64\bin`).
- If an older inventory lacks `Architecture`, remediation infers architecture from the current DLL file before replacement.
- Cached ZIPs are validate/services. Schedule during maintenance windows where possible.
- Some embedded/vendor DLLs may not have a clean d before use; corrupt/incomplete downloads are automatically removed and re-downloaded.
- Remediation validates current DLL hash against detection inventory before replacing (drift protection).
- Remediation checks whether target DLL/backup files are locked or inaccessible; locked/in-use files are skipped instead of failing the entire run.
- Replacing in-use DLLs may fail for locked filesmapping to distributable OpenSSL package layouts.
- Always pilot this remediation on test rings before broad deployment.
