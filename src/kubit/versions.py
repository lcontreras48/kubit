import re
from dataclasses import dataclass


@dataclass(frozen=True, order=True)
class Version:
    major: int
    minor: int
    patch: int = 0

    @property
    def series(self) -> str:
        return f"{self.major}.{self.minor}"


def parse(value: str) -> Version | None:
    """Extract a SemVer-like version from Kubernetes, image, and OS strings."""
    match = re.search(r"(?<!\d)(\d+)\.(\d+)(?:\.(\d+))?", value or "")
    if not match:
        return None
    return Version(int(match[1]), int(match[2]), int(match[3] or 0))


def image_tag(image: str) -> str:
    without_digest = image.split("@", 1)[0]
    tail = without_digest.rsplit("/", 1)[-1]
    return tail.rsplit(":", 1)[1] if ":" in tail else "unknown"
