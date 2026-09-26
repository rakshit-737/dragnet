"""Typed data model for DRAGNET."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class SignalKind(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    FILE_HASH = "file_hash"
    IMPHASH = "imphash"
    CODE_REUSE = "code_reuse"      # shared function/code-block fingerprint
    FAMILY = "family"
    TTP = "ttp"                    # MITRE ATT&CK technique id
    VICTIMOLOGY = "victimology"
    RICH_HEADER = "rich_header"    # PE Rich header: known to be forgeable
    LANGUAGE = "language"          # strings/locale artifacts: forgeable
    MUTEX = "mutex"


# Default per-kind evidential weight in [0, 1]. Transparent + overridable.
DEFAULT_WEIGHTS: dict[SignalKind, float] = {
    SignalKind.IP: 0.55,
    SignalKind.DOMAIN: 0.6,
    SignalKind.FILE_HASH: 0.9,
    SignalKind.IMPHASH: 0.6,
    SignalKind.CODE_REUSE: 0.75,
    SignalKind.FAMILY: 0.5,
    SignalKind.TTP: 0.15,
    SignalKind.VICTIMOLOGY: 0.1,
    SignalKind.RICH_HEADER: 0.35,
    SignalKind.LANGUAGE: 0.15,
    SignalKind.MUTEX: 0.4,
}

# Kinds an adversary can cheaply plant to frame someone else.
FORGEABLE_KINDS = frozenset({SignalKind.RICH_HEADER, SignalKind.LANGUAGE, SignalKind.MUTEX})
# Kinds that are hard to fake and anchor an attribution.
HARD_KINDS = frozenset({SignalKind.IP, SignalKind.DOMAIN, SignalKind.FILE_HASH,
                        SignalKind.IMPHASH, SignalKind.CODE_REUSE})


class Confidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INSUFFICIENT = "INSUFFICIENT"


@dataclass(frozen=True)
class Signal:
    kind: SignalKind
    value: str
    source: str = ""          # evidence item id that produced it

    @property
    def key(self) -> tuple[str, str]:
        return (self.kind.value, self.value.lower())

    @property
    def label(self) -> str:
        return f"{self.kind.value}:{self.value}"


@dataclass
class EvidenceItem:
    id: str
    kind: str                 # "forensic" | "malware"
    content: dict
    sha256: str = ""


@dataclass
class Campaign:
    id: str
    name: str
    actor: str
    signals: list[Signal] = field(default_factory=list)


@dataclass
class HypothesisScore:
    hypothesis: str
    support: float
    contradiction: float
    score: float
    matched: list[Signal] = field(default_factory=list)
    contradicting: list[Signal] = field(default_factory=list)


@dataclass
class Assessment:
    case_id: str
    leading: str | None
    confidence: Confidence
    hypotheses: list[HypothesisScore]
    matrix: dict[str, dict[str, str]]      # signal-label -> hypothesis -> C/I/N
    false_flag_indicators: list[str]
    raise_confidence: list[str]
    lower_confidence: list[str]
    custody: list[dict]
    weights: dict[str, float]
    links: list[tuple[str, str, str]] = field(default_factory=list)
