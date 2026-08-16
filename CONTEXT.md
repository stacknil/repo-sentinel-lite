# Project Context

This file defines stable domain language for architecture and maintenance work.
It complements user documentation; it is not a release-status claim.

## Baseline Reconciliation

**Baseline Reconciliation** is the authoritative comparison of persisted baseline
findings with findings from the current scan. `reconcile_baseline()` owns all
matching, classification, consumption, and suppression decisions. Public baseline
operations are projections of that result:

- `apply_baseline()` returns current findings that are not suppressible matches.
- `prune_baseline()` retains only current findings backed by reliable suppressible
  matches.
- `audit_baseline()` exposes classifications, review reasons, ambiguous candidates,
  and unmatched current findings.

### Invariants

1. Exact fingerprints are resolved globally before weaker identities.
2. A current finding is consumed by at most one baseline decision.
3. Raw tokens and their persisted redacted SHA-256 evidence have equivalent
   content-matching semantics.
4. Input order does not change classification, matching choice, or output order.
5. Ambiguous relocation fails closed: candidates stay visible, remain unmatched,
   and do not justify pruning a baseline entry.
6. Classification and suppression are separate decisions. In particular,
   `rule_changed` remains suppressible while its compatibility state stays visible
   in audit output.

### Classification vocabulary

- `active`: a reliable match with no detected rule-version drift.
- `rule_changed`: a reliable match whose rule version changed or whose persisted
  version is unknown.
- `relocated`: the same comparable content identity at a different line.
- `changed`: the same rule and location with different content identity.
- `stale`: no current candidate can be matched.
- `ambiguous`: multiple plausible assignments prevent a reliable match.

Only `active`, `rule_changed`, and `relocated` are suppressible. `changed`, `stale`,
and `ambiguous` never hide current findings.
