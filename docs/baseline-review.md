# Baseline Review Guide

Baselines are reviewable suppression files. They let a repository keep known
findings visible in version control without failing every scan forever.

See [`examples/sample-baseline.json`](../examples/sample-baseline.json) for a
small synthetic baseline.

## What a baseline suppresses

A baseline suppresses findings that match entries in the baseline JSON file.
`repo-sentinel-lite` currently records these finding kinds:

- `high_entropy`: a high-entropy token at a file and line
- `missing_file`: a required repository file that is absent
- `suspicious_file`: a suspicious filename such as `.env`, `*.pem`, `*.key`,
  `id_rsa`, or `*.kdbx`
- `pem_private_key`: a PEM private-key header
- `github_token`: a GitHub-token-like prefix
- `aws_access_key_id`: an AWS access-key-like identifier
- `assignment_context`: a secret-adjacent assignment context such as
  `token=` or `api_key=`

Each current finding also includes `rule_id`, `rule_version`, `severity`,
`fingerprint`, `evidence`, and `remediation_hint`. The legacy `kind` field is
kept so older baseline entries remain readable.

When a baseline entry has a `fingerprint`, matching prefers that fingerprint.
Legacy entries without fingerprints still match by finding identity, such as
kind plus path, or kind plus file, line, token, and entropy for high-entropy
findings.

Apply an explicit baseline with:

```bash
repo-sentinel scan --baseline baseline.json .
```

If `.reposentinel-baseline.json` exists in the scanned repository root,
`repo-sentinel scan .` applies it automatically unless
`--no-default-baseline` is passed.

## What it does not prove

A baseline does not prove that a finding is safe. It only records that the
finding was reviewed and intentionally suppressed for this repository state.

A baseline also does not prove:

- that a high-entropy token is harmless
- that a suspicious file is safe to publish
- that missing repository files are acceptable forever
- that new findings outside the baseline will be ignored

Reviewers should treat baseline changes like security-adjacent code changes:
small, explicit, and explained in the commit or pull request.

## How redaction works

High-entropy token values are redacted by default in CLI output and generated
baselines. Redacted values look like:

```text
<redacted:sha256:3eb1bd439947>
```

The suffix is a short SHA-256 digest prefix of the token value. This keeps
baseline files deterministic enough to review without writing the raw token
body to the repository.

Use `--reveal-secrets` only for local investigation:

```bash
repo-sentinel scan --reveal-secrets .
```

Do not commit revealed token values. If a real secret was committed, rotate or
revoke it; redaction and history cleanup are not substitutes for revocation.

## How to review baseline drift

Review baseline drift by comparing the current scan, the existing baseline, and
a refreshed candidate baseline.

1. Run a scan without the default root baseline when you need to see all current
   findings:

```bash
repo-sentinel scan --no-default-baseline .
```

2. Run with the committed baseline to confirm only new unsuppressed findings
   remain:

```bash
repo-sentinel scan --baseline .reposentinel-baseline.json .
```

3. Write a refreshed candidate baseline for review:

```bash
repo-sentinel scan \
  --baseline .reposentinel-baseline.json \
  --update-baseline .reposentinel-baseline.next.json \
  .
```

4. Diff the old and new files. Review each added, removed, or moved finding.
   Added entries need an explanation. Removed entries are usually good news, but
   still confirm they disappeared because the underlying issue was fixed or the
   path was intentionally removed.

5. Prune stale entries when you only want to keep suppressions that still match
   current findings:

```bash
repo-sentinel scan \
  --baseline .reposentinel-baseline.json \
  --prune-baseline .reposentinel-baseline.pruned.json \
  .
```

6. Audit the committed baseline when you need classification instead of a
   rewritten candidate file:

```bash
repo-sentinel baseline audit --baseline .reposentinel-baseline.json .
```

The audit output groups entries as:

- `active`: a baseline entry still matches a current finding
- `stale`: a baseline entry no longer matches any current finding
- `ambiguous`: a baseline entry points at the same rule and location but no
  longer has a matching fingerprint
- `unmatched`: a current finding is not covered by the baseline

Treat `ambiguous` and `unmatched` entries as review prompts. Do not silently
refresh them without checking why the fingerprint or rule evidence changed.

## Allowlists and Scoped Exceptions

Use a baseline for reviewed findings that should remain visible as committed
suppression state. Use an allowlist only for narrower exceptions where the
finding should not be emitted at all for that repository configuration.

`.reposentinel.toml` supports:

```toml
[allowlist]
paths = ["fixtures/**"]
rules = ["repo.suspicious_filename"]
token_hashes = ["sha256:3eb1bd439947"]
```

Inline scoped comments are also supported for one-line fixture exceptions:

```text
# repo-sentinel: allow secret.assignment_context
api_key=example_fixture_value
```

Prefer the narrowest exception that explains the fixture. Avoid broad
rule-level allowlists in repositories that still need secret-adjacent review.

## How fail-on-findings behaves

`--fail-on-findings` evaluates the report after baseline suppression is applied.
If the baseline suppresses every current finding, the command exits `0` even
when the unsuppressed scan would have findings.

```bash
repo-sentinel scan \
  --baseline .reposentinel-baseline.json \
  --fail-on-findings \
  .
```

New findings that are not in the baseline remain in the report and make
`--fail-on-findings` exit `1`.

For severity-specific gates, use `--fail-on-severity warning` or
`--fail-on-severity error`. These gates also run after baseline suppression.
