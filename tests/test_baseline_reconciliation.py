from __future__ import annotations

from itertools import permutations

import repo_sentinel.baseline as baseline_module
import repo_sentinel.report as report_module
from repo_sentinel.baseline import (
    apply_baseline,
    audit_baseline,
    baseline_from_report,
    extract_baseline_findings,
    prune_baseline,
)
from repo_sentinel.baseline_matching import (
    BaselineClassification,
    reconcile_baseline,
)
from repo_sentinel.redaction import redact_baseline
from repo_sentinel.report import build_report, extract_findings


def _finding(
    *, line: int, token: str = "shorttok9", rule_version: str | None = None
) -> dict[str, object]:
    finding: dict[str, object] = {
        "kind": "assignment_context",
        "file": "tokens.txt",
        "line": line,
        "token": token,
    }
    if rule_version is not None:
        finding["rule_version"] = rule_version
    return finding


def _reconcile(
    current: dict[str, object], baseline: dict[str, object]
):
    return reconcile_baseline(
        baseline_findings=extract_baseline_findings(baseline),
        current_findings=extract_findings(current),
    )


def test_ambiguous_relocation_remains_visible_and_is_not_pruned() -> None:
    baseline = baseline_from_report(build_report([_finding(line=1)], {}))
    current = build_report([_finding(line=2), _finding(line=3)], {})

    audit = audit_baseline(current, baseline)
    suppressed = apply_baseline(current, baseline)
    pruned = prune_baseline(current, baseline)

    assert audit["summary"]["ambiguous"] == 1
    assert audit["summary"]["unmatched"] == 2
    assert [
        finding["line"] for finding in audit["ambiguous"][0]["candidates"]
    ] == [2, 3]
    assert [finding["line"] for finding in suppressed["findings"]] == [2, 3]
    assert pruned["findings"] == []


def test_many_baselines_cannot_consume_one_current_finding() -> None:
    baseline = baseline_from_report(
        build_report([_finding(line=1), _finding(line=2)], {})
    )
    current = build_report([_finding(line=3)], {})

    reconciliation = _reconcile(current, baseline)

    assert [
        decision.classification for decision in reconciliation.decisions
    ] == [BaselineClassification.AMBIGUOUS, BaselineClassification.AMBIGUOUS]
    assert all(not decision.suppress for decision in reconciliation.decisions)
    assert [finding["line"] for finding in reconciliation.remaining_current] == [3]
    assert [finding["line"] for finding in reconciliation.unmatched_current] == [3]
    assert reconciliation.retained_current == ()


def test_reconciliation_is_permutation_invariant_and_exact_first() -> None:
    baseline = baseline_from_report(
        build_report([_finding(line=1), _finding(line=2)], {})
    )
    current = build_report([_finding(line=2), _finding(line=3)], {})
    baseline_findings = extract_baseline_findings(baseline)
    current_findings = extract_findings(current)
    signatures: set[tuple[tuple[object, ...], ...]] = set()

    for baseline_order in permutations(baseline_findings):
        for current_order in permutations(current_findings):
            reconciliation = reconcile_baseline(
                baseline_findings=baseline_order,
                current_findings=current_order,
            )
            signatures.add(
                tuple(
                    (
                        decision.baseline["line"],
                        decision.classification,
                        (
                            decision.current["line"]
                            if decision.current is not None
                            else None
                        ),
                        decision.suppress,
                    )
                    for decision in reconciliation.decisions
                )
            )
            assert reconciliation.remaining_current == ()
            assert reconciliation.unmatched_current == ()

    assert signatures == {
        (
            (1, BaselineClassification.RELOCATED, 3, True),
            (2, BaselineClassification.ACTIVE, 2, True),
        )
    }


def test_redacted_digest_matches_plaintext_relocation() -> None:
    baseline = redact_baseline(
        baseline_from_report(build_report([_finding(line=1)], {}))
    )
    current = build_report([_finding(line=8)], {})

    reconciliation = _reconcile(current, baseline)

    assert len(reconciliation.decisions) == 1
    decision = reconciliation.decisions[0]
    assert decision.classification is BaselineClassification.RELOCATED
    assert decision.suppress
    assert decision.current is not None
    assert decision.current["line"] == 8
    assert reconciliation.remaining_current == ()


def test_rule_changed_classification_remains_suppressible() -> None:
    baseline = baseline_from_report(
        build_report([_finding(line=2, rule_version="1")], {})
    )
    current = build_report([_finding(line=2, rule_version="2")], {})

    reconciliation = _reconcile(current, baseline)
    suppressed = apply_baseline(current, baseline)
    pruned = prune_baseline(current, baseline)
    audit = audit_baseline(current, baseline)

    assert len(reconciliation.decisions) == 1
    decision = reconciliation.decisions[0]
    assert decision.classification is BaselineClassification.RULE_CHANGED
    assert decision.suppress
    assert suppressed["findings"] == []
    assert [finding["line"] for finding in pruned["findings"]] == [2]
    assert audit["summary"]["rule_changed"] == 1


def test_reconciliation_is_the_only_matching_surface() -> None:
    assert not hasattr(baseline_module, "baseline_match_keys")
    assert not hasattr(report_module, "finding_matches_baseline")
