# Contributing to OSC

Thanks for wanting to contribute. OSC is open source and welcomes pull
requests from anyone.

## Before you start

- **License:** OSC is licensed under [AGPL-3.0-or-later](LICENSE). By
  submitting a contribution, you agree it is licensed under the same
  terms, and that you have the right to submit it under that license.
- **Scope:** This is a security-testing tool. New features that touch
  active probing (`osc/active_scan.py`) get extra scrutiny for legal/
  safety impact - see the LEGAL WARNING in [README.md](README.md).

## Setting up a dev environment

```bash
git clone https://github.com/Fannandya/security-checker.git
cd security-checker
python3 -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -e ".[dev,recon]"
```

## Running tests

```bash
pytest -v
```

The test suite (`tests/`) makes no real network calls - it uses `responses`
to mock HTTP. Tests must pass on Python 3.8, 3.10, and 3.12 (see
`.github/workflows/ci.yml`); if you use newer syntax (e.g. f-string
grammar changes from PEP 701), verify it against Python 3.8-3.11 too,
since those use the stricter pre-3.12 f-string grammar.

## Making a change

1. Fork the repo and create a branch off `main`.
2. Keep changes focused - one logical change per pull request.
3. Add or update tests for any behavior change.
4. Run `pytest -v` locally and make sure it's green.
5. If you added a new finding category or check, update the relevant
   table in `README.md` (Security Posture Audit / Recon Categories) so
   documentation and code stay in sync.
6. Add yourself to [AUTHORS.md](AUTHORS.md) in the same PR.
7. Open a pull request describing what changed and why.

## Reporting bugs / false positives

Open a GitHub issue with:
- The command/flags used (redact the target URL if it's not public).
- Expected vs. actual finding.
- Whether it reproduces against a fresh clone with no local changes.

## Code style

- No hard dependency on network access in `tests/`.
- Prefer plain dicts/functions over new classes unless there's real
  shared state to encapsulate (matches the existing `osc/recon.py`,
  `osc/security_audit.py` style).
- New source files should carry the same SPDX header as the rest of
  `osc/` (`SPDX-License-Identifier: AGPL-3.0-or-later`).
