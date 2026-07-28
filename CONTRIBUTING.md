# Contributing

Thanks for taking the time to contribute.

This project automates one specific stack — Cloudflare for domains and DNS,
Google Workspace for mailboxes, Clay for campaigns — on purpose. Before
proposing a new integration or a general-purpose option, check the
[design choices](README.md#design-choices-worth-knowing) and
[what is automated, and what is not](README.md#what-is-automated-and-what-is-not)
sections; a lot of "why doesn't it just..." questions are answered there.

## Before you start

- For a bug, open an issue with the **Bug report** template first, unless
  you already have a fix ready.
- For a new feature or a behavior change, open an issue with the
  **Feature request** template so the approach can be discussed before you
  write code. This is especially worth doing for anything that touches
  record writing, verification, or the state file — mistakes there can cost
  someone money or break a domain's mail delivery.
- For small fixes (typos, docs, an obvious off-by-one), a pull request
  without a preceding issue is fine.

Everyone participating is expected to follow the
[Code of Conduct](CODE_OF_CONDUCT.md).

## Setting up your environment

Needs Python 3.11 or newer.

```bash
git clone https://github.com/Convergent-AI-Solutions/google-workspace-clay-domain-provisioner.git
cd google-workspace-clay-domain-provisioner
python -m venv .venv
source .venv/bin/activate   # .venv\Scripts\Activate.ps1 on Windows
pip install -e ".[dev]"
```

This installs the `gwclay` command, plus `pytest`, `hypothesis`, and `ruff`.
See the [README's Install section](README.md#install) if activation is not
an option in your setup.

## Making a change

- Run the test suite and linter before opening a pull request:

  ```bash
  pytest tests/
  ruff check .
  ```

- The codebase separates pure logic from the network layer on purpose:
  candidate generation, record building and normalisation, verification
  judgements, and record matching all live in code that takes no network
  clients, so they can be unit tested directly. Keep new logic in that
  shape where you can, rather than folding it into the Cloudflare or
  Google client modules.
- Add or update tests alongside any behavior change. If you're touching
  record parsing, matching, or normalisation, consider whether a
  [Hypothesis](https://hypothesis.readthedocs.io/) property test is
  appropriate — see `tests/test_dns_records_property.py` and
  `tests/test_suggest_property.py` for existing examples. Property tests
  should skip cleanly if Hypothesis is not installed.
- Match the existing `ruff` configuration in `pyproject.toml`
  (line length 100, target Python 3.11) rather than introducing your own
  formatting.
- No credential, secret, or real domain name belonging to a person or
  organization should ever appear in a commit, test fixture, or example.
  Use placeholder domains like `example.com` or `getexample.com`,
  consistent with the README.

## Submitting a pull request

- Keep pull requests focused on one change. Unrelated fixes are easier to
  review, and to revert if something goes wrong, as their own PRs.
- Fill in the pull request template — it asks for what changed, why, and
  how you verified it (test output, or a manual run with `--dry-run`).
- Make sure CI (lint + tests on Python 3.11, 3.12, and 3.13) passes.
- Update `README.md` if you change user-facing behavior: a command's
  flags, what a step automates, or a documented default.

## Reporting security issues

Do not open a public issue for a suspected vulnerability, especially
anything involving credential handling or DNS record writes. See
[SECURITY.md](SECURITY.md) for how to report it privately.
