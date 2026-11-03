# Redaction Notes

This package was mechanically redacted with an env-driven redactor/leak-scanner
(kept internal, not shipped) before assembly, then scanned. The redaction rules were:

## What is redacted (and why)
| Category | Pattern → replacement | Why |
|----------|-----------------------|-----|
| Username | `<username>` → `<redacted>` | Personal identity |
| Home paths | `/home/<username>`, `/var/home/<username>` → `/home/<redacted>` | Personal identity |
| Account IDs | numeric account IDs → `<redacted-account-id>` | Account identity |
| Passport | `NP12:...` → `<redacted-passport>` | Session credential |
| csauth token | `csauthtoken` values → `<redacted-token>` | Session credential |
| lifetoken GUID | lifetoken GUID → `<redacted-guid>` | Session credential |
| **Researcher handle** | `REDACT_HANDLES` entries → "the external researcher" (+ possessive) | At operator's request, a third-party contributor's handle is removed throughout |

The handle rule (env var `REDACT_HANDLES`, comma-separated) rewrites each handle to "the
external researcher" and its possessive form to "the external researcher's", and is
**included in the leak scan** so a reintroduced handle fails the check.

## What is intentionally KEPT
Technical facts that are properties of the **client/anti-cheat**, not the operator:
- Nexon IPs / hostnames
- Client constants: the 2-key 3DES/DES-EDE2 asset key, module CRCs, RVAs/addresses, opcodes
- Cipher parameters (AES layout, verMask, seeds, shuffle tables)

These are reproducible from the shipped binary and carry no personal data.

## Verification performed on this package
- Scan of `docs`, `evidence`, and `tools-QUARANTINE` with the redactor → **CLEAN**
- Belt-and-braces case-insensitive grep for the username, the researcher handle, and any
  `ghp_` token across all files → **0 hits**

## Note on secrets
No GitHub token, password, or session credential is stored anywhere in this package or its
git history. If this drop is published, the token shared during research should be rotated —
it was over-privileged and shared in-band.
