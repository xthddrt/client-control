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
| Session IDs | session identifiers → `<redacted-session-id>` | Session identity |
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

## Original verification (superseded by the recovery review below)
- Scan of `docs`, `evidence`, `foundations`, `analysis`, and `tools` with the redactor → **CLEAN**
- Belt-and-braces case-insensitive grep for the username, the researcher handle, and any
  `ghp_` token across all files → **0 hits**

## Consolidated recovery review (2026-11-04)

- Parsed every evidence JSON file and recursively checked account/passport/session-token fields: values remain marked with the documented redaction placeholders.
- Scanned documentation, evidence, and source for GitHub-token and credential-shaped values: no unredacted match was found.
- Found that two copies of the documented base64 decode sample produced an unredacted session token. Replaced both with synthetic samples containing `<redacted-token>`, redacted a session identifier, reran both samples, and scanned all long base64 candidates in `docs` and `evidence`: **CLEAN**.
- Removed the pre-redaction absolute workspace paths from all Python callers; intentional redaction examples in these notes are unchanged.
- The internal redactor, original username/handle lists, and pre-redaction sources were not shipped. This review cannot independently reproduce their exact comparisons or prove the absence of identifiers that are not recognizable from the redacted drop.

## Note on secrets
No known unredacted GitHub token, password, or session credential remains in the recovered
working tree. This review does not rewrite existing publication history or external archives.
The token shared during research should be rotated — it was over-privileged and shared in-band.
