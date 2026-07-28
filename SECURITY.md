# Security Policy

## Supported Versions

This project is pre-1.0 and ships from a single line of development. Security
fixes land on `main` and in the most recent release; there are no parallel
maintenance branches.

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Scope

This tool holds several categories of sensitive material while it runs:
Cloudflare API tokens, Google Workspace service-account keys or OAuth
client secrets, generated mailbox passwords, and DKIM key material pasted
from the Admin console. Reports about any of the following are in scope:

- Credentials or secrets appearing anywhere other than `.env` (gitignored,
  supplied by you) — for example printed to logs or written into
  `.provisioner-state/<domain>.json`, which is designed to hold only
  non-secret progress state.
- DNS record writes that could overwrite or weaken an unrelated record
  (for example, clobbering an SPF or Google site-verification TXT record
  at the zone apex).
- Verification logic that could report a forged or attacker-controlled
  record as valid.
- Any code path that sends a credential to somewhere other than the
  Cloudflare or Google API it was intended for.

Issues in Cloudflare's, Google's, or Clay's own platforms are out of scope
here — report those directly to the respective vendor.

## Reporting a Vulnerability

Please do not open a public GitHub issue for a suspected vulnerability.

Instead, report it privately using
[GitHub Security Advisories](https://github.com/Convergent-AI-Solutions/google-workspace-clay-domain-provisioner/security/advisories/new)
for this repository, or by emailing **security@convergent.consulting** with
as much of the following as you can provide:

- A description of the issue and its potential impact.
- Steps to reproduce, or a proof of concept.
- The version or commit you tested against.

We aim to acknowledge new reports within 3 business days, and to give you an
initial assessment (accepted, needs more information, or declined) within
10 business days. If accepted, we will work with you on a fix and a
disclosure timeline, and credit you in the release notes unless you prefer
to stay anonymous. If declined, we will explain why.
