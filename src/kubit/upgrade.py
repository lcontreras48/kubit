from dataclasses import replace

from .engine import Engine
from .models import Component, Result
from .versions import parse


def evaluate_kubernetes_target(
    components: list[Component],
    rule_document: dict,
    target_version: str,
) -> tuple[list[Component], list[Result]]:
    if not parse(target_version):
        raise ValueError("target Kubernetes version must contain major.minor[.patch]")
    normalized = target_version if target_version.startswith("v") else f"v{target_version}"
    hypothetical = [
        replace(component, version=normalized, source="upgrade-simulation")
        if component.name in {"kubernetes", "kube-apiserver"}
        else component
        for component in components
    ]
    return hypothetical, Engine(rule_document).evaluate(hypothetical)
