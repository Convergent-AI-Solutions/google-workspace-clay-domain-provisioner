# cold-email-domain-provisioner

Provision a new cold-email sending domain end to end: pick an available `.com`,
register it with Cloudflare, add it to Google Workspace as a secondary domain,
create the sending mailbox, publish the MX, SPF, DKIM and DMARC records, verify
them against public resolvers, and prepare the Clay import.

Nothing in this tool is specific to any company. Every value comes from a
command-line flag, an environment variable, or an interactive prompt.

## What is automated, and what is not

Two of the seven steps cannot be fully automated today, because the providers
expose no application programming interface (API) for them. The tool does the
automatable part of each and hands you the rest with the exact values you need.

| Step | Status | How |
| --- | --- | --- |
| 1. Suggest available `.com` domains | Automated | Cloudflare Registrar `domain-search` and `domain-check` |
| 2. Register the domain | Automated | Cloudflare Registrar `registrations` |
| 3. Add as a Workspace secondary domain and verify ownership | Automated | Admin SDK `domains.insert`, then Site Verification API with a DNS TXT token |
| 4. Create the sending mailbox | Automated | Admin SDK `users.insert` |
| 5. MX, SPF and DMARC records | Automated | Cloudflare DNS API |
| 5. DKIM record | **Half manual** | Google generates the key pair and shows the public half only in the Admin console. The tool prints the exact path, waits for you to paste the value, then publishes and checks the TXT record. |
| 6. Verify all four records | Automated | Public DNS resolvers, not Cloudflare's own API |
| 7. Add the mailbox to Clay with warmup on | **Manual** | Clay connects mailboxes through OAuth, manual SMTP entry, or an SMTP CSV upload, all in its own interface. It publishes no endpoint for adding an email account or enabling warmup. The tool writes the CSV and a checklist. |

### Why DKIM cannot be automated

Google generates the DKIM key pair, keeps the private half, and exposes the
public half only in the Admin console. Google Workspace does not accept an
imported key, so there is no way to compute or supply the `p=` value yourself.
Publishing the record once you have that value is a normal Cloudflare TXT write,
which this tool does.

### Why the Clay step cannot be automated

As of 2026-07, Clay's documented ways to add a sending mailbox are Google
OAuth, Microsoft OAuth, and SMTP entered manually or uploaded as a CSV. There is
no documented REST endpoint for creating an email account or toggling warmup.
Two consequences:

- The CSV column names in [`clay.py`](src/cold_email_domain_provisioner/clay.py)
  are a starting point, not a verified contract. Clay does not publish its
  upload schema. Check them against the upload dialog the first time, then pin
  whatever it actually asks for.
- The SMTP password cannot be filled in automatically. Gmail SMTP needs an app
  password, app passwords require 2-step verification on the account, and Google
  exposes no API for creating one. The CSV ships a placeholder.

## Prerequisites

**Cloudflare**

- An API token with **Registrar write** and **Zone DNS edit** permissions.
- A default payment method on the billing profile. Registration fails without one.
- A default registrant contact configured, or supply the WHOIS fields yourself.
- The Domain Registration Agreement accepted on the account.

The Registrar registration API entered beta in April 2026. Two limits follow:
top-level domain support is limited, and renewals, transfers and contact updates
are not available through the API. This tool treats the `domain-check` response
as authoritative on whether a given `.com` can be registered, and reports
"unknown" rather than guessing when the response omits an availability field.

**Google Workspace**

- Either a service-account key with domain-wide delegation, or an OAuth
  client-secrets file you sign in with as a super admin.
- These scopes:
  - `https://www.googleapis.com/auth/admin.directory.domain`
  - `https://www.googleapis.com/auth/admin.directory.user`
  - `https://www.googleapis.com/auth/siteverification`
- A spare licence. Each user created on a secondary domain consumes one.

A **secondary domain** is not a **domain alias**. An alias mirrors the addresses
of existing users; a secondary domain holds its own users. A sending mailbox
needs its own account, so this tool adds a secondary domain.

## Install

```bash
git clone https://github.com/Convergent-AI-Solutions/cold-email-domain-provisioner.git
cd cold-email-domain-provisioner
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

Python 3.11 or newer. The command is `cedp`.

## Configure

Copy `.env.example` to `.env` and fill in what you want defaulted. Precedence is
command-line flag, then environment variable, then interactive prompt, so you can
supply nothing up front and answer questions as they come.

`.env` is gitignored. No credential is ever written to the run-state file, and
the mailbox password is printed once and not saved.

## Use

### One step at a time

```bash
cedp suggest example.com --limit 20 --available-only
```

```bash
cedp purchase getexample.com
```

```bash
cedp workspace getexample.com
```

```bash
cedp mailbox getexample.com --local-part connect
```

```bash
cedp records getexample.com --dmarc-rua dmarc@example.com
```

```bash
cedp dkim getexample.com
```

```bash
cedp verify getexample.com
```

```bash
cedp clay getexample.com
```

### All of it

```bash
cedp run example.com --dmarc-rua dmarc@example.com
```

`run` chains every step, pauses at the DKIM prompt, and finishes by writing a
handoff checklist listing what is left to do in Clay.

### Check where a domain got to

```bash
cedp status getexample.com
```

## Safety

Registration spends money and cannot be reversed, so:

- `--dry-run` works on every command and makes no changes.
- `purchase` requires you to type the domain name back before it registers
  anything. `--yes` skips that, for scripted use.
- Ownership is checked before registering, so a resumed run never pays twice.
- Every step records completion in `.provisioner-state/<domain>.json` before the
  next one starts, and a re-run skips what is already done.
- A record write is an upsert matched on record identity, not just name. The SPF
  record and the Google ownership token both live at the zone apex, and matching
  on name alone would overwrite one with the other.
- Nothing is deleted unless you pass `--prune-stale-mx`, which removes MX records
  outside the expected set. Use it when switching between the single-host and
  five-host Google MX layouts.

Waiting is jittered: every poll sleeps a base interval plus a random extra, so
concurrent runs do not synchronise their retries against a recovering service.

## Design choices worth knowing

**Verification reads public resolvers, not Cloudflare.** Reading records back
from the API you just wrote to confirms what you asked for, not what a receiving
mail server sees. Verification queries public recursive resolvers (8.8.8.8 and
1.1.1.1 by default, configurable) with the local resolver configuration
bypassed, so a split-horizon corporate resolver cannot mask a missing record.

**DMARC starts at `p=none`.** A new domain has no reputation and no report
history. Tighten to `quarantine` or `reject` once aggregate reports show only
your own mail passing. The policy, the report address and the percentage are all
configurable.

**Two SPF records is a failure, not a warning.** RFC 7208 makes more than one
`v=spf1` record on a name a permanent error, and receivers treat it as no SPF at
all. The verifier fails on it.

**Candidate names are deliberately unimaginative.** The generator applies a small
set of prefixes and suffixes to your domain's root label. It does not produce
misspellings or lookalikes, because a sending domain a recipient cannot connect
to your business hurts reply rates. Hyphenated variants are opt-in.

## Sending responsibly

This tool sets up authenticated sending infrastructure. It does not send mail
and takes no view on your list. Cold outbound email is regulated in most
jurisdictions, including the CAN-SPAM Act in the United States, the Privacy and
Electronic Communications Regulations in the United Kingdom, and the Spam Act
2003 in Australia. Accurate sender identification, a working unsubscribe path,
and a lawful basis for contacting a recipient are your responsibility.

## Development

```bash
pytest tests/
```

```bash
ruff check .
```

The pure logic is separated from the network layer so it can be tested directly:
candidate generation, record building and normalisation, the verification
judgements, and record matching all have unit tests, plus Hypothesis property
tests for the parts where an off-by-one character would silently break mail
authentication. Property tests skip cleanly if Hypothesis is not installed.

## Licence

MIT. See [LICENSE](LICENSE).
