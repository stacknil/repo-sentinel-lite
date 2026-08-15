from __future__ import annotations

import json
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import cast

from .report import (
    baseline_finding_identity,
    baseline_finding_sort_key,
    coerce_finding,
    finding_content_identity,
    finding_fingerprint,
    finding_rule_location_identity,
)


class BaselineClassification(StrEnum):
    ACTIVE = "active"
    RULE_CHANGED = "rule_changed"
    RELOCATED = "relocated"
    CHANGED = "changed"
    STALE = "stale"
    AMBIGUOUS = "ambiguous"


_MATCHED_CLASSIFICATIONS = frozenset(
    {
        BaselineClassification.ACTIVE,
        BaselineClassification.RULE_CHANGED,
        BaselineClassification.RELOCATED,
        BaselineClassification.CHANGED,
    }
)
_SUPPRESSIBLE_CLASSIFICATIONS = frozenset(
    {
        BaselineClassification.ACTIVE,
        BaselineClassification.RULE_CHANGED,
        BaselineClassification.RELOCATED,
    }
)


@dataclass(frozen=True, slots=True)
class BaselineDecision:
    classification: BaselineClassification
    suppress: bool
    baseline: dict[str, object]
    current: dict[str, object] | None = None
    candidates: tuple[dict[str, object], ...] = ()
    reason: str | None = None

    def __post_init__(self) -> None:
        has_current = self.current is not None
        if has_current != (self.classification in _MATCHED_CLASSIFICATIONS):
            raise ValueError(
                f"{self.classification} decision has invalid current finding state"
            )
        if self.classification == BaselineClassification.AMBIGUOUS:
            if not self.candidates:
                raise ValueError("ambiguous decision requires candidates")
        elif self.candidates:
            raise ValueError(
                f"{self.classification} decision cannot contain candidates"
            )
        expected_suppression = (
            self.classification in _SUPPRESSIBLE_CLASSIFICATIONS
        )
        if self.suppress != expected_suppression:
            raise ValueError(
                f"{self.classification} decision has invalid suppression state"
            )


@dataclass(frozen=True, slots=True)
class BaselineReconciliation:
    decisions: tuple[BaselineDecision, ...]
    remaining_current: tuple[dict[str, object], ...]
    retained_current: tuple[dict[str, object], ...]
    unmatched_current: tuple[dict[str, object], ...]


@dataclass(slots=True)
class _FindingEntry:
    index: int
    finding: dict[str, object]
    _identities: dict[str, tuple[object, ...]] = field(
        default_factory=dict, init=False, repr=False
    )

    @property
    def fingerprint(self) -> str | None:
        value = self.finding.get("fingerprint")
        return value if isinstance(value, str) else None

    def content_identity(self) -> tuple[object, ...]:
        return self._identity(
            "content", lambda: finding_content_identity(self.finding)
        )

    def location_identity(self) -> tuple[object, ...]:
        def build() -> tuple[object, ...]:
            content_identity = self.content_identity()
            return (
                content_identity
                if "line" not in self.finding
                else (*content_identity, int(self.finding["line"]))
            )

        return self._identity("location", build)

    def rule_location_identity(self) -> tuple[object, ...]:
        return self._identity(
            "rule_location",
            lambda: finding_rule_location_identity(self.finding),
        )

    def legacy_identity(self) -> tuple[object, ...]:
        return self._identity(
            "legacy", lambda: baseline_finding_identity(self.finding)
        )

    def _identity(
        self,
        name: str,
        build: Callable[[], tuple[object, ...]],
    ) -> tuple[object, ...]:
        if name not in self._identities:
            self._identities[name] = build()
        return self._identities[name]


@dataclass(frozen=True, slots=True)
class _MatchPolicy:
    classification: BaselineClassification
    reason: str | None
    ambiguous_reason: str
    classify_rule_change: bool = False


_EXACT_POLICY = _MatchPolicy(
    BaselineClassification.ACTIVE,
    None,
    "multiple baseline or current findings share the same fingerprint",
    True,
)
_LOCATION_POLICY = _MatchPolicy(
    BaselineClassification.ACTIVE,
    None,
    "multiple current findings share the same location identity",
    True,
)
_RELOCATION_POLICY = _MatchPolicy(
    BaselineClassification.RELOCATED,
    "same content identity at a different line",
    "multiple current findings share the same content identity",
    True,
)
_RULE_LOCATION_POLICY = _MatchPolicy(
    classification=BaselineClassification.CHANGED,
    reason="same rule and location with different content identity",
    ambiguous_reason="multiple current findings share the same rule and location",
)
_LEGACY_POLICY = _MatchPolicy(
    classification=BaselineClassification.ACTIVE,
    reason=None,
    ambiguous_reason="multiple current findings share the legacy identity",
    classify_rule_change=True,
)


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
        _validate_fingerprint_invariant(self.baselines)
        _validate_fingerprint_invariant(self.current)
        self.decisions: dict[int, BaselineDecision] = {}
        self.consumed: set[int] = set()
        self.suppressed: set[int] = set()
        self.blocked: set[int] = set()

    def run(self) -> BaselineReconciliation:
        self._resolve_exact_fingerprints()
        self._resolve_content_identities()
        self._resolve_grouped_identity(
            lambda entry: entry.rule_location_identity(),
            _RULE_LOCATION_POLICY,
        )
        self._resolve_grouped_identity(
            lambda entry: entry.legacy_identity(),
            _LEGACY_POLICY,
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
        return BaselineReconciliation(
            decisions=decisions,
            remaining_current=tuple(
                entry.finding
                for entry in self.current
                if entry.index not in self.suppressed
            ),
            retained_current=tuple(
                entry.finding
                for entry in self.current
                if entry.index in self.suppressed
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
                if entry.fingerprint is not None
            ),
            lambda entry: cast(str, entry.fingerprint),
        )
        current = _groups(
            self.current,
            lambda entry: cast(str, entry.fingerprint),
        )
        for fingerprint in sorted(baselines):
            baseline_group = baselines[fingerprint]
            current_group = current.get(fingerprint, [])
            self._resolve_candidates(
                baseline_group, current_group, _EXACT_POLICY
            )

    def _resolve_content_identities(self) -> None:
        baselines = _content_groups(self._pending_baselines())
        current = _content_groups(self._available_current())
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
            lambda entry: entry.location_identity(),
        )
        current_locations = _groups(
            current,
            lambda entry: entry.location_identity(),
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
            self._resolve_candidates(
                baseline_group, current_group, _LOCATION_POLICY
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
        self._resolve_candidates(
            remaining_baselines, remaining_current, _RELOCATION_POLICY
        )

    def _resolve_grouped_identity(
        self,
        identity: Callable[[_FindingEntry], tuple[object, ...]],
        policy: _MatchPolicy,
    ) -> None:
        baselines = _groups(self._pending_baselines(), identity)
        current = _groups(self._available_current(), identity)
        for match_identity in sorted(baselines, key=_stable_identity_key):
            self._resolve_candidates(
                baselines[match_identity],
                current.get(match_identity, []),
                policy,
            )

    def _resolve_candidates(
        self,
        baselines: list[_FindingEntry],
        current: list[_FindingEntry],
        policy: _MatchPolicy,
    ) -> None:
        if not baselines or not current:
            return
        if len(baselines) == len(current) == 1:
            self._record_match(
                baselines[0],
                current[0],
                policy.classification,
                policy.reason,
                classify_rule_change=policy.classify_rule_change,
            )
        else:
            self._record_ambiguity(
                baselines,
                current,
                policy.ambiguous_reason,
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
        suppress = resolved in _SUPPRESSIBLE_CLASSIFICATIONS
        self.decisions[baseline.index] = BaselineDecision(
            classification=resolved,
            suppress=suppress,
            baseline=baseline.finding,
            current=current.finding,
            reason=rule_change_reason or reason,
        )
        self.consumed.add(current.index)
        if suppress:
            self.suppressed.add(current.index)

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
        item = (
            coerce_finding(finding, preserve_fingerprint=True)
            if current
            else coerce_baseline_finding(finding)
        )
        if current and "fingerprint" not in item:
            item["fingerprint"] = finding_fingerprint(item)
        normalized.append(item)
    normalized.sort(key=_stable_finding_sort_key)
    return [
        _FindingEntry(index=index, finding=finding)
        for index, finding in enumerate(normalized)
    ]


def coerce_baseline_finding(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError("baseline findings entries must be objects")
    normalized = coerce_finding(value, preserve_fingerprint=True)
    persisted_rule_version = value.get("rule_version")
    if not isinstance(persisted_rule_version, str) or not persisted_rule_version:
        normalized.pop("rule_version", None)
    return normalized


def _groups(
    entries: Iterable[_FindingEntry],
    identity: Callable[[_FindingEntry], object],
) -> dict[object, list[_FindingEntry]]:
    grouped: dict[object, list[_FindingEntry]] = {}
    for entry in entries:
        grouped.setdefault(identity(entry), []).append(entry)
    return grouped


def _content_groups(
    entries: Iterable[_FindingEntry],
) -> dict[object, list[_FindingEntry]]:
    grouped: dict[object, list[_FindingEntry]] = {}
    for entry in entries:
        identity = entry.content_identity()
        if _identity_is_comparable(identity):
            grouped.setdefault(identity, []).append(entry)
    return grouped


def _validate_fingerprint_invariant(entries: list[_FindingEntry]) -> None:
    first_by_fingerprint: dict[str, _FindingEntry] = {}
    for entry in entries:
        fingerprint = entry.fingerprint
        if fingerprint is None:
            continue
        previous = first_by_fingerprint.setdefault(fingerprint, entry)
        if (
            previous is not entry
            and previous.location_identity() != entry.location_identity()
        ):
            raise ValueError(
                "fingerprint collision for distinct findings: " f"{fingerprint}"
            )


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
    "coerce_baseline_finding",
    "reconcile_baseline",
]
