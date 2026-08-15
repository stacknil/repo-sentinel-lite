from __future__ import annotations

import json
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from enum import StrEnum

from .report import (
    baseline_finding_identity,
    baseline_finding_sort_key,
    coerce_finding,
    finding_content_identity,
    finding_fingerprint,
    finding_location_identity,
    finding_rule_location_identity,
    validate_fingerprint_invariant,
)


class BaselineClassification(StrEnum):
    ACTIVE = "active"
    RULE_CHANGED = "rule_changed"
    RELOCATED = "relocated"
    CHANGED = "changed"
    STALE = "stale"
    AMBIGUOUS = "ambiguous"


@dataclass(frozen=True, slots=True)
class BaselineDecision:
    classification: BaselineClassification
    suppress: bool
    baseline: dict[str, object]
    current: dict[str, object] | None = None
    candidates: tuple[dict[str, object], ...] = ()
    reason: str | None = None


@dataclass(frozen=True, slots=True)
class BaselineReconciliation:
    decisions: tuple[BaselineDecision, ...]
    remaining_current: tuple[dict[str, object], ...]
    retained_current: tuple[dict[str, object], ...]
    unmatched_current: tuple[dict[str, object], ...]


@dataclass(frozen=True, slots=True)
class _FindingEntry:
    index: int
    finding: dict[str, object]


def reconcile_baseline(
    *,
    baseline_findings: Sequence[dict[str, object]],
    current_findings: Sequence[dict[str, object]],
) -> BaselineReconciliation:
    """Reconcile baseline and current findings with one matching policy.

    Exact fingerprints are resolved globally before weaker identities. A current
    finding is consumed by at most one reliable match. Ambiguous candidates are
    never consumed, suppressed, or retained by pruning.
    """
    return _Reconciler(baseline_findings, current_findings).run()


class _Reconciler:
    def __init__(
        self,
        baseline_findings: Sequence[dict[str, object]],
        current_findings: Sequence[dict[str, object]],
    ) -> None:
        self.baselines = _entries(baseline_findings, current=False)
        self.current = _entries(current_findings, current=True)
        validate_fingerprint_invariant(
            [entry.finding for entry in self.baselines]
        )
        validate_fingerprint_invariant(
            [entry.finding for entry in self.current]
        )
        self.decisions: dict[int, BaselineDecision] = {}
        self.consumed: set[int] = set()
        self.blocked: set[int] = set()

    def run(self) -> BaselineReconciliation:
        self._resolve_exact_fingerprints()
        self._resolve_content_identities()
        self._resolve_grouped_identity(
            finding_rule_location_identity,
            BaselineClassification.CHANGED,
            "same rule and location with different content identity",
            "multiple current findings share the same rule and location",
        )
        self._resolve_grouped_identity(
            baseline_finding_identity,
            BaselineClassification.ACTIVE,
            None,
            "multiple current findings share the legacy identity",
            classify_rule_change=True,
        )
        for baseline in self.baselines:
            if baseline.index not in self.decisions:
                self.decisions[baseline.index] = BaselineDecision(
                    BaselineClassification.STALE,
                    False,
                    baseline.finding,
                )

        decisions = tuple(
            self.decisions[entry.index] for entry in self.baselines
        )
        current_indexes = {
            id(entry.finding): entry.index for entry in self.current
        }
        suppressed = {
            current_indexes[id(decision.current)]
            for decision in decisions
            if decision.suppress and decision.current is not None
        }
        return BaselineReconciliation(
            decisions=decisions,
            remaining_current=tuple(
                entry.finding
                for entry in self.current
                if entry.index not in suppressed
            ),
            retained_current=tuple(
                entry.finding
                for entry in self.current
                if entry.index in suppressed
            ),
            unmatched_current=tuple(
                entry.finding
                for entry in self.current
                if entry.index not in self.consumed
            ),
        )

    def _resolve_exact_fingerprints(self) -> None:
        baselines = _groups(
            (
                entry
                for entry in self.baselines
                if isinstance(entry.finding.get("fingerprint"), str)
            ),
            lambda entry: str(entry.finding["fingerprint"]),
        )
        current = _groups(
            self.current,
            lambda entry: str(entry.finding["fingerprint"]),
        )
        for fingerprint in sorted(baselines):
            baseline_group = baselines[fingerprint]
            current_group = current.get(fingerprint, [])
            if not current_group:
                continue
            if len(baseline_group) == len(current_group) == 1:
                self._record_match(
                    baseline_group[0],
                    current_group[0],
                    BaselineClassification.ACTIVE,
                    None,
                    classify_rule_change=True,
                )
            else:
                self._record_ambiguity(
                    baseline_group,
                    current_group,
                    "multiple baseline or current findings share the same fingerprint",
                )

    def _resolve_content_identities(self) -> None:
        comparable = finding_content_identity
        baselines = _groups(
            (
                entry
                for entry in self._pending_baselines()
                if _identity_is_comparable(comparable(entry.finding))
            ),
            lambda entry: comparable(entry.finding),
        )
        current = _groups(
            (
                entry
                for entry in self._available_current()
                if _identity_is_comparable(comparable(entry.finding))
            ),
            lambda entry: comparable(entry.finding),
        )
        for identity in sorted(baselines, key=_stable_identity_key):
            baseline_group = baselines[identity]
            current_group = current.get(identity, [])
            if not current_group:
                continue
            self._resolve_same_content_locations(baseline_group, current_group)

    def _resolve_same_content_locations(
        self,
        baselines: list[_FindingEntry],
        current: list[_FindingEntry],
    ) -> None:
        baseline_locations = _groups(
            baselines,
            lambda entry: finding_location_identity(entry.finding),
        )
        current_locations = _groups(
            current,
            lambda entry: finding_location_identity(entry.finding),
        )
        shared_locations = sorted(
            set(baseline_locations) & set(current_locations),
            key=_stable_identity_key,
        )
        for location in shared_locations:
            baseline_group = [
                entry
                for entry in baseline_locations[location]
                if entry.index not in self.decisions
            ]
            current_group = [
                entry
                for entry in current_locations[location]
                if entry.index not in self.consumed
                and entry.index not in self.blocked
            ]
            if not baseline_group or not current_group:
                continue
            if len(baseline_group) == len(current_group) == 1:
                self._record_match(
                    baseline_group[0],
                    current_group[0],
                    BaselineClassification.ACTIVE,
                    None,
                    classify_rule_change=True,
                )
            else:
                self._record_ambiguity(
                    baseline_group,
                    current_group,
                    "multiple current findings share the same location identity",
                )

        remaining_baselines = [
            entry for entry in baselines if entry.index not in self.decisions
        ]
        remaining_current = [
            entry
            for entry in current
            if entry.index not in self.consumed
            and entry.index not in self.blocked
        ]
        if len(remaining_baselines) == len(remaining_current) == 1:
            self._record_match(
                remaining_baselines[0],
                remaining_current[0],
                BaselineClassification.RELOCATED,
                "same content identity at a different line",
                classify_rule_change=True,
            )
        elif remaining_baselines and remaining_current:
            self._record_ambiguity(
                remaining_baselines,
                remaining_current,
                "multiple current findings share the same content identity",
            )

    def _resolve_grouped_identity(
        self,
        identity: Callable[[dict[str, object]], tuple[object, ...]],
        classification: BaselineClassification,
        reason: str | None,
        ambiguous_reason: str,
        *,
        classify_rule_change: bool = False,
    ) -> None:
        baselines = _groups(
            self._pending_baselines(),
            lambda entry: identity(entry.finding),
        )
        current = _groups(
            self._available_current(),
            lambda entry: identity(entry.finding),
        )
        for match_identity in sorted(baselines, key=_stable_identity_key):
            baseline_group = baselines[match_identity]
            current_group = current.get(match_identity, [])
            if not current_group:
                continue
            if len(baseline_group) == len(current_group) == 1:
                self._record_match(
                    baseline_group[0],
                    current_group[0],
                    classification,
                    reason,
                    classify_rule_change=classify_rule_change,
                )
            else:
                self._record_ambiguity(
                    baseline_group,
                    current_group,
                    ambiguous_reason,
                )

    def _record_match(
        self,
        baseline: _FindingEntry,
        current: _FindingEntry,
        classification: BaselineClassification,
        reason: str | None,
        *,
        classify_rule_change: bool,
    ) -> None:
        if baseline.index in self.decisions or current.index in self.consumed:
            raise AssertionError("baseline reconciliation consumed a finding twice")
        rule_change_reason = (
            _rule_version_change_reason(baseline.finding, current.finding)
            if classify_rule_change
            else None
        )
        resolved = (
            BaselineClassification.RULE_CHANGED
            if rule_change_reason is not None
            else classification
        )
        self.decisions[baseline.index] = BaselineDecision(
            classification=resolved,
            suppress=resolved
            in {
                BaselineClassification.ACTIVE,
                BaselineClassification.RULE_CHANGED,
                BaselineClassification.RELOCATED,
            },
            baseline=baseline.finding,
            current=current.finding,
            reason=rule_change_reason or reason,
        )
        self.consumed.add(current.index)

    def _record_ambiguity(
        self,
        baselines: list[_FindingEntry],
        current: list[_FindingEntry],
        reason: str,
    ) -> None:
        candidates = tuple(entry.finding for entry in current)
        for baseline in baselines:
            if baseline.index not in self.decisions:
                self.decisions[baseline.index] = BaselineDecision(
                    BaselineClassification.AMBIGUOUS,
                    False,
                    baseline.finding,
                    candidates=candidates,
                    reason=reason,
                )
        self.blocked.update(entry.index for entry in current)

    def _pending_baselines(self) -> Iterable[_FindingEntry]:
        return (
            entry
            for entry in self.baselines
            if entry.index not in self.decisions
        )

    def _available_current(self) -> Iterable[_FindingEntry]:
        return (
            entry
            for entry in self.current
            if entry.index not in self.consumed
            and entry.index not in self.blocked
        )


def _entries(
    findings: Sequence[dict[str, object]], *, current: bool
) -> list[_FindingEntry]:
    normalized: list[dict[str, object]] = []
    for finding in findings:
        item = coerce_finding(finding, preserve_fingerprint=True)
        if current and "fingerprint" not in item:
            item["fingerprint"] = finding_fingerprint(item)
        elif not current:
            rule_version = finding.get("rule_version")
            if not isinstance(rule_version, str) or not rule_version:
                item.pop("rule_version", None)
        normalized.append(item)
    normalized.sort(key=_stable_finding_sort_key)
    return [
        _FindingEntry(index=index, finding=finding)
        for index, finding in enumerate(normalized)
    ]


def _groups(
    entries: Iterable[_FindingEntry],
    identity: Callable[[_FindingEntry], object],
) -> dict[object, list[_FindingEntry]]:
    grouped: dict[object, list[_FindingEntry]] = {}
    for entry in entries:
        grouped.setdefault(identity(entry), []).append(entry)
    return grouped


def _identity_is_comparable(identity: tuple[object, ...]) -> bool:
    return not (len(identity) == 3 and identity[-1] is None)


def _rule_version_change_reason(
    baseline: dict[str, object], current: dict[str, object]
) -> str | None:
    if baseline.get("rule_id") != current.get("rule_id"):
        return None
    baseline_version = baseline.get("rule_version")
    current_version = current.get("rule_version")
    if not isinstance(baseline_version, str) or not baseline_version:
        return "unknown baseline rule version"
    if baseline_version != current_version:
        return f"rule version changed from {baseline_version} to {current_version}"
    return None


def _stable_finding_sort_key(finding: dict[str, object]) -> tuple[object, ...]:
    return (
        *baseline_finding_sort_key(finding),
        json.dumps(finding, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
    )


def _stable_identity_key(identity: object) -> str:
    return json.dumps(identity, ensure_ascii=False, sort_keys=True, default=str)


__all__ = [
    "BaselineClassification",
    "BaselineDecision",
    "BaselineReconciliation",
    "reconcile_baseline",
]
