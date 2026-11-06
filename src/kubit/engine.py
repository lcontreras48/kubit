from dataclasses import replace
from datetime import date
import re

from .models import Component, Result
from .versions import parse


class Engine:
    def __init__(self, rule_document: dict, today: date | None = None):
        self.document = rule_document
        self.rules = rule_document["rules"]
        self.today = today or date.today()

    def evaluate(self, components: list[Component]) -> list[Result]:
        by_name: dict[str, list[Component]] = {}
        for component in components:
            by_name.setdefault(component.name, []).append(component)

        results: list[Result] = []
        evaluated: set[tuple[str, str, str]] = set()
        for rule in self.rules:
            subjects = by_name.get(rule["subject"], [])
            if rule["type"] == "version_spread":
                results.extend(self._version_spread(rule, subjects))
                evaluated.update((subject.name, subject.version, subject.instance) for subject in subjects)
                continue
            dependencies = by_name.get(rule["dependency"], [])
            for subject in subjects:
                matching_dependencies = [
                    dependency
                    for dependency in dependencies
                    if not rule.get("match_instance") or dependency.instance == subject.instance
                ]
                if rule.get("evidence_status") == "stale":
                    results.append(self._stale(rule, subject, matching_dependencies))
                elif matching_dependencies:
                    candidates = [self._evaluate_rule(rule, subject, dependency) for dependency in matching_dependencies]
                    results.append(self._aggregate(candidates))
                else:
                    results.append(self._missing_dependency(rule, subject))
                evaluated.add((subject.name, subject.version, subject.instance))

        ignored = {"kubernetes", "crds"}
        for component in components:
            key = (component.name, component.version, component.instance)
            if (
                key not in evaluated
                and component.name not in ignored
                and not component.metadata.get("application_group")
            ):
                results.append(
                    Result(
                        component.name,
                        component.version,
                        "none",
                        "unknown",
                        "unknown",
                        "No compatibility rule is defined for this component.",
                        "no-rule",
                        "",
                        component.instance,
                    )
                )
        return results

    def _evaluate_rule(self, rule: dict, subject: Component, dependency: Component) -> Result:
        if rule["type"] == "version_skew":
            return self._version_skew(rule, subject, dependency)
        if rule["type"] == "matrix":
            return self._matrix(rule, subject, dependency)
        if rule["type"] == "minimum_version":
            return self._minimum_version(rule, subject, dependency)
        if rule["type"] == "subject_minimum":
            return self._subject_minimum(rule, subject, dependency)
        if rule["type"] == "catalog_matrix":
            return self._catalog_matrix(rule, subject, dependency)
        if rule["type"] == "constraint_matrix":
            return self._constraint_matrix(rule, subject, dependency)
        raise ValueError(f"unknown rule type: {rule['type']}")

    def _constraint_matrix(self, rule: dict, subject: Component, dependency: Component) -> Result:
        entry = next(
            (
                item
                for item in rule["entries"]
                if (
                    item.get("subject_exact", "").removeprefix("v")
                    == subject.version.removeprefix("v")
                    if item.get("subject_exact")
                    else any(
                        _matches_constraint(subject.version, constraint)
                        for constraint in item["subject_constraints"]
                    )
                )
            ),
            None,
        )
        if not entry:
            return self._result(
                rule,
                subject,
                dependency,
                "unknown",
                rule.get("missing_entry_reason", "No source-backed requirement covers this component version."),
            )
        covered = any(
            _matches_constraint(dependency.version, constraint)
            for constraint in entry["dependency_constraints"]
        )
        if not covered:
            return self._result(
                rule,
                subject,
                dependency,
                rule.get("outside_status", "unknown"),
                entry.get("outside_reason", rule.get("outside_reason", "The dependency version is outside documented coverage.")),
            )
        return self._result(
            rule,
            subject,
            dependency,
            entry.get("status", "supported"),
            entry.get("reason", rule.get("supported_reason", "The combination is covered by upstream evidence.")),
        )

    def _catalog_matrix(self, rule: dict, subject: Component, dependency: Component) -> Result:
        entry = next(
            (
                item
                for item in rule["entries"]
                if _matches_constraint(subject.version, item["subject_constraint"])
            ),
            None,
        )
        if not entry:
            return self._result(
                rule,
                subject,
                dependency,
                "unknown",
                "compatibility.fyi has no source-backed entry covering this deployed component version.",
            )
        evidence_rule = {
            **rule,
            "evidence": entry["source_url"],
            "evidence_title": entry["source_title"],
            "evidence_basis": entry["basis"],
            "evidence_confidence": entry["confidence"],
            "evidence_verified_at": entry["last_verified"],
        }
        subject_version, dependency_version = parse(subject.version), parse(dependency.version)
        covered = bool(
            entry.get("same_version")
            and subject_version
            and dependency_version
            and subject_version == dependency_version
        )
        covered = covered or any(
            _matches_constraint(dependency.version, constraint)
            for constraint in entry["dependency_ranges"]
        )
        if not covered:
            return self._result(
                evidence_rule,
                subject,
                dependency,
                "unknown",
                "The catalog has primary evidence for this component version, but it does not cover the deployed Kubernetes version.",
            )
        verified_at = _iso_date(entry["last_verified"])
        if not verified_at:
            return self._result(evidence_rule, subject, dependency, "unknown", "Catalog evidence has no valid verification date.")
        if verified_at > self.today:
            return self._result(evidence_rule, subject, dependency, "unknown", "Catalog verification date is in the future.")
        if (self.today - verified_at).days > rule.get("max_evidence_age_days", 180):
            return self._result(evidence_rule, subject, dependency, "stale", "Catalog evidence is older than the accepted verification window.")
        if entry["confidence"] != "high":
            return self._result(evidence_rule, subject, dependency, "unknown", "Catalog evidence is not high confidence.")
        basis = entry["basis"]
        status = entry["catalog_status"]
        note = entry["notes"][0] if entry["notes"] else "The version range is backed by primary upstream evidence."
        if status == "incompatible":
            return self._result(evidence_rule, subject, dependency, "incompatible", note)
        if status == "compatible" and basis in {"supported", "tested"}:
            return self._result(evidence_rule, subject, dependency, "supported", note)
        reason = f"Catalog evidence is {basis or 'unclassified'} and cannot establish support."
        return self._result(evidence_rule, subject, dependency, "unknown", reason)

    def _version_skew(self, rule: dict, subject: Component, dependency: Component) -> Result:
        subject_version, dependency_version = parse(subject.version), parse(dependency.version)
        status, reason = "unknown", "One or both versions could not be parsed."
        if subject_version and dependency_version:
            skew = dependency_version.minor - subject_version.minor
            wrong_major = subject_version.major != dependency_version.major
            max_older = rule["max_older_minors"]
            max_newer = rule.get("max_newer_minors", 0)
            legacy_before = parse(rule.get("legacy_before_series", ""))
            if legacy_before and subject_version < legacy_before:
                max_older = rule.get("legacy_max_older_minors", max_older)
                max_newer = rule.get("legacy_max_newer_minors", max_newer)
            newer_violation = skew < 0 and (rule.get("never_newer") or -skew > max_newer)
            if wrong_major or newer_violation or skew > max_older:
                status = "incompatible"
                reason = (
                    f"{rule['subject']} {subject.version} is outside the supported skew "
                    f"for {rule['dependency']} {dependency.version}."
                )
            else:
                status = "supported"
                reason = "Version skew is within the documented Kubernetes policy."
        return self._result(rule, subject, dependency, status, reason)

    def _version_spread(self, rule: dict, subjects: list[Component]) -> list[Result]:
        if not subjects:
            return []
        if rule.get("evidence_status") == "stale":
            return [self._stale(rule, subjects[0], subjects[1:])]
        parsed = [(subject, parse(subject.version)) for subject in subjects]
        if any(version is None for _, version in parsed):
            status, reason = "unknown", "One or more component versions could not be parsed."
        else:
            versions = [version for _, version in parsed if version]
            majors = {version.major for version in versions}
            spread = max(version.minor for version in versions) - min(version.minor for version in versions)
            if len(majors) > 1 or spread > rule["max_minor_spread"]:
                status, reason = "incompatible", "Component instances exceed the documented HA version spread."
            else:
                status, reason = "supported", "Component instances are within the documented HA version spread."
        ordered = sorted(subjects, key=lambda item: parse(item.version) or parse("0.0.0"))
        return [self._result(rule, ordered[-1], ordered[0], status, reason, instance="cluster")]

    def _matrix(self, rule: dict, subject: Component, dependency: Component) -> Result:
        subject_version, dependency_version = parse(subject.version), parse(dependency.version)
        if not subject_version or not dependency_version:
            return self._result(rule, subject, dependency, "unknown", "One or both versions could not be parsed.")
        entry = next((item for item in rule["entries"] if item["subject_series"] == subject_version.series), None)
        if not entry:
            return self._result(
                rule,
                subject,
                dependency,
                "unknown",
                rule.get("missing_entry_reason", "No verified matrix entry exists for this version."),
            )
        if not entry.get("currently_supported", True):
            return self._result(rule, subject, dependency, "unsupported", "Release is listed as an old or unsupported release.")
        if entry.get("end_of_life") and self.today > date.fromisoformat(entry["end_of_life"]):
            return self._result(rule, subject, dependency, "unsupported", f"Release reached end of life on {entry['end_of_life']}.")
        if dependency_version.series not in entry["supported_dependency_series"]:
            if dependency_version.series in entry.get("tested_dependency_series", []):
                reason = "Dependency is tested by the project but explicitly not supported."
            else:
                reason = rule.get("unsupported_reason", "Dependency is outside the official support matrix.")
            return self._result(rule, subject, dependency, rule.get("outside_status", "unsupported"), reason)
        return self._result(
            rule,
            subject,
            dependency,
            "supported",
            rule.get("supported_reason", "Combination is listed in the official support matrix."),
        )

    def _minimum_version(self, rule: dict, subject: Component, dependency: Component) -> Result:
        subject_version, dependency_version = parse(subject.version), parse(dependency.version)
        if not subject_version or not dependency_version:
            return self._result(rule, subject, dependency, "unknown", "One or both versions could not be parsed.")
        entry = next(
            (
                item
                for item in rule["entries"]
                if (
                    not item.get("subject_min_version")
                    or subject_version >= parse(item["subject_min_version"])
                )
                and (
                    not item.get("subject_max_exclusive")
                    or subject_version < parse(item["subject_max_exclusive"])
                )
            ),
            None,
        )
        if not entry:
            return self._result(rule, subject, dependency, "unknown", "No verified requirement exists for this component version.")
        minimum = parse(entry["minimum_dependency_version"])
        if not minimum:
            return self._result(rule, subject, dependency, "unknown", "Official minimum dependency version could not be parsed.")
        if dependency_version < minimum:
            conditional = parse(entry.get("conditional_minimum_dependency_version", ""))
            if conditional and dependency_version >= conditional:
                reason = (
                    f"{dependency.name} {dependency.version} requires the documented condition: "
                    f"{entry.get('condition', 'additional upstream requirements')}."
                )
                return self._result(rule, subject, dependency, "unknown", reason)
            reason = f"{dependency.name} {dependency.version} is below the documented minimum {entry['minimum_dependency_version']}."
            return self._result(rule, subject, dependency, "incompatible", reason)
        reason = f"{dependency.name} {dependency.version} meets the documented minimum {entry['minimum_dependency_version']}."
        return self._result(rule, subject, dependency, "supported", reason)

    def _subject_minimum(self, rule: dict, subject: Component, dependency: Component) -> Result:
        subject_version = parse(subject.version)
        minimum = parse(rule["minimum_subject_version"])
        if not subject_version or not minimum:
            return self._result(rule, subject, dependency, "unknown", "Component version or official minimum could not be parsed.")
        if subject_version < minimum:
            reason = f"{subject.name} {subject.version} is below the minimum {rule['minimum_subject_version']} supported by {dependency.name}."
            return self._result(rule, subject, dependency, "incompatible", reason)
        reason = f"{subject.name} {subject.version} meets the minimum {rule['minimum_subject_version']} supported by {dependency.name}."
        return self._result(rule, subject, dependency, "supported", reason)

    def _missing_dependency(self, rule: dict, subject: Component) -> Result:
        return Result(
            subject.name,
            subject.version,
            rule["dependency"],
            "not-detected",
            "unknown",
            f"Required dependency {rule['dependency']} was not detected.",
            rule["id"],
            rule["evidence"],
            subject.instance,
            rule.get("evidence_status", "unknown"),
            rule.get("evidence_retrieved_at", ""),
            rule.get("evidence_checksum", ""),
            rule.get("provider", ""),
            rule.get("evidence_title", ""),
            rule.get("evidence_basis", ""),
            rule.get("evidence_confidence", ""),
            rule.get("evidence_verified_at", ""),
        )

    def _stale(self, rule: dict, subject: Component, dependencies: list[Component]) -> Result:
        dependency = dependencies[0] if dependencies else Component(rule.get("dependency", subject.name), "unknown", "none")
        return self._result(rule, subject, dependency, "stale", "Official compatibility evidence is stale.")

    @staticmethod
    def _aggregate(candidates: list[Result]) -> Result:
        severity = {"supported": 0, "unknown": 1, "stale": 2, "unsupported": 3, "incompatible": 4}
        worst = max(candidates, key=lambda result: severity.get(result.status, 1))
        if len(candidates) == 1:
            return worst
        versions = sorted({result.dependency_version for result in candidates})
        reason = worst.reason
        if worst.status == "supported":
            reason = f"All {len(candidates)} detected dependency instances satisfy the documented policy."
        return replace(worst, dependency_version=",".join(versions), reason=reason)

    @staticmethod
    def _result(
        rule: dict,
        subject: Component,
        dependency: Component,
        status: str,
        reason: str,
        instance: str | None = None,
    ) -> Result:
        return Result(
            subject.name,
            subject.version,
            dependency.name,
            dependency.version,
            status,
            reason,
            rule["id"],
            rule["evidence"],
            instance or subject.instance,
            rule.get("evidence_status", "unknown"),
            rule.get("evidence_retrieved_at", ""),
            rule.get("evidence_checksum", ""),
            rule.get("provider", ""),
            rule.get("evidence_title", ""),
            rule.get("evidence_basis", ""),
            rule.get("evidence_confidence", ""),
            rule.get("evidence_verified_at", ""),
        )


def _iso_date(value: str) -> date | None:
    try:
        return date.fromisoformat(value)
    except (TypeError, ValueError):
        return None


def _matches_constraint(value: str, expression: str) -> bool:
    version = parse(value)
    if not version or not isinstance(expression, str):
        return False
    return any(_matches_constraint_group(version, group.strip()) for group in expression.split("||"))


def _matches_constraint_group(version, group: str) -> bool:
    hyphen = re.fullmatch(r"\s*(v?\d+(?:\.\d+){0,2})\s+-\s+(v?\d+(?:\.\d+){0,2})\s*", group)
    if hyphen:
        lower, upper = parse(hyphen.group(1)), parse(hyphen.group(2))
        return bool(lower and upper and lower <= version <= upper)
    group = re.sub(r"(>=|<=|>|<|=|~)\s+(?=v?\d)", r"\1", group)
    tokens = group.split()
    if not tokens:
        return False
    return all(_matches_constraint_token(version, token) for token in tokens)


def _matches_constraint_token(version, token: str) -> bool:
    match = re.fullmatch(r"(>=|<=|>|<|=|~)?v?(\d+(?:\.\d+){0,2})(?:[-+][0-9A-Za-z.-]+)?", token)
    if not match:
        return False
    operator, raw = match.group(1) or "", match.group(2)
    target = parse(raw)
    if not target:
        return False
    if operator == ">=":
        return version >= target
    if operator == "<=":
        return version <= target
    if operator == ">":
        return version > target
    if operator == "<":
        return version < target
    parts = raw.split(".")
    if operator == "~":
        return version.major == target.major and version.minor == target.minor and version >= target
    if len(parts) == 1:
        return version.major == target.major
    if len(parts) == 2:
        return version.major == target.major and version.minor == target.minor
    return version == target
