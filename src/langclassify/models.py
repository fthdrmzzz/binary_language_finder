from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal


Language = Literal[
    "C", "C++", "Go", "Rust", "Python", "Perl", "Shell", "Java", "JavaScript", ".NET",
    "Ruby", "PHP", "Lua",
    "Other", "Missing", "Unreadable", "Directory"
]

@dataclass(frozen=True)
class Evidence:
    kind: str         # e.g. "shebang", "magic", "elf_section", "elf_symbol", "pe_clr", "token"
    value: str        # human-readable
    weight: float     # 0..1, used for scoring
    via: str          # e.g. "python", "readelf", "nm", "file", "zipfile"

@dataclass
class Classification:
    path: str
    language: Language
    confidence: float
    evidence: list[Evidence] = field(default_factory=list)
    file_kind: str = ""      # "script", "elf", "pe", "zip", "text", "unknown", etc.
    details: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

