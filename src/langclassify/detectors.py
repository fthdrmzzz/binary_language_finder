from __future__ import annotations

import os
import stat
from collections import defaultdict
from dataclasses import dataclass
from typing import Iterable

from .models import Classification, Evidence, Language
from .parsers import (
    ELF_MAGIC, JAVA_CLASS_MAGIC, ZIP_MAGIC, MZ_MAGIC,
    read_prefix, read_first_line_bytes, parse_shebang,
    is_probably_text, is_jar, parse_pe_for_dotnet,
)
from .tools import ToolRunner


@dataclass(frozen=True)
class Candidate:
    lang: Language
    score: float
    evidence: list[Evidence]


def _clamp01(x: float) -> float:
    return 0.0 if x < 0 else 1.0 if x > 1.0 else x


def _sum_weight(evs: Iterable[Evidence]) -> float:
    return sum(ev.weight for ev in evs)


def _normalise(score: float) -> float:
    # Map raw score to [0,1] with diminishing returns.
    return _clamp01(1.0 - (2.718281828 ** (-score)))


def classify_path(path: str, tools: ToolRunner, use_ldd: bool = False, use_strings_tool: bool = False) -> Classification:
    out = Classification(path=path, language="Other", confidence=0.0)

    try:
        st = os.lstat(path)
    except FileNotFoundError:
        out.language = "Missing"
        out.confidence = 0.0
        return out
    except OSError as e:
        out.language = "Unreadable"
        out.errors.append(str(e))
        return out

    if stat.S_ISDIR(st.st_mode):
        out.language = "Directory"
        out.file_kind = "directory"
        out.confidence = 0.2
        out.evidence.append(Evidence("fs", "is directory", 0.2, "python"))
        return out

    if not stat.S_ISREG(st.st_mode):
        out.file_kind = "special"
        out.language = "Other"
        out.confidence = 0.2
        out.evidence.append(Evidence("fs", "not a regular file", 0.2, "python"))
        return out

    try:
        prefix = read_prefix(path, 8192)
    except OSError as e:
        out.language = "Unreadable"
        out.errors.append(str(e))
        return out

    # Stage: shebang
    try:
        line = read_first_line_bytes(path)
        sb = parse_shebang(line) if line else None
    except OSError:
        sb = None

    if sb is not None:
        interp, opt = sb
        out.file_kind = "script"
        out.evidence.append(Evidence("shebang", f"{interp} {opt or ''}".strip(), 1.0, "python"))

        lang, conf = classify_shebang(interp, opt)
        out.language = lang
        out.confidence = conf
        return out

    # Stage: magic/container
    if prefix.startswith(JAVA_CLASS_MAGIC):
        out.file_kind = "java_class"
        out.language = "Java"
        out.confidence = 0.99
        out.evidence.append(Evidence("magic", "CAFEBABE (Java class)", 1.0, "python"))
        return out

    if prefix.startswith(ZIP_MAGIC):
        out.file_kind = "zip"
        try:
            if is_jar(path):
                out.language = "Java"
                out.confidence = 0.98
                out.evidence.append(Evidence("container", "ZIP with JAR markers (manifest/class)", 1.0, "zipfile"))
            else:
                out.language = "Other"
                out.confidence = 0.4
                out.evidence.append(Evidence("container", "ZIP (non-JAR)", 0.4, "zipfile"))
            return out
        except Exception as e:
            out.errors.append(f"zip parse failed: {e!r}")
            out.language = "Other"
            out.confidence = 0.2
            return out

    if prefix.startswith(MZ_MAGIC):
        pe = parse_pe_for_dotnet(path)
        if pe.is_pe:
            out.file_kind = "pe"
            out.evidence.append(Evidence("magic", "MZ/PE (Portable Executable)", 0.7, "python"))
            if pe.com_descriptor_rva and pe.com_descriptor_rva != 0:
                out.evidence.append(Evidence("pe_clr", f"COM descriptor present (RVA=0x{pe.com_descriptor_rva:x}, size=0x{pe.com_descriptor_size:x})", 1.0, "python"))
            if pe.bs_jb_found:
                out.evidence.append(Evidence("pe_metadata", "BSJB metadata root signature found", 1.0, "python"))
            out.details.update({
                "machine": pe.machine,
                "pe_magic": pe.pe_magic,
                "com_descriptor_rva": pe.com_descriptor_rva,
                "com_descriptor_size": pe.com_descriptor_size,
                "bsjb": pe.bs_jb_found,
            })
            out.errors.extend(pe.errors)
            if pe.is_dotnet:
                out.language = ".NET"
                out.confidence = 0.97 if pe.bs_jb_found else 0.90
            else:
                out.language = "Other"
                out.confidence = 0.5
            return out

    # Stage: ELF
    if prefix.startswith(ELF_MAGIC):
        out.file_kind = "elf"
        cands = classify_elf(path, tools, use_ldd=use_ldd, use_strings_tool=use_strings_tool)
        best = max(cands, key=lambda c: c.score) if cands else Candidate("Other", 0.0, [])
        out.language = best.lang
        out.evidence.extend(best.evidence)
        out.confidence = _normalise(best.score)
        return out

    # Stage: text heuristics
    if is_probably_text(prefix):
        out.file_kind = "text"
        cands = classify_text_no_shebang(path, prefix)
        best = max(cands, key=lambda c: c.score) if cands else Candidate("Other", 0.0, [])
        out.language = best.lang
        out.evidence.extend(best.evidence)
        out.confidence = _normalise(best.score)
        return out

    out.file_kind = "unknown"
    out.language = "Other"
    out.confidence = 0.2
    out.evidence.append(Evidence("magic", "unknown/unsupported", 0.2, "python"))
    return out


def classify_shebang(interp: str, opt: str | None) -> tuple[Language, float]:
    # Normalise env usage: /usr/bin/env <cmd>
    base = os.path.basename(interp)
    cmd = opt if base == "env" and opt else base

    cmd_l = (cmd or "").lower()
    if "python" in cmd_l:
        return "Python", 0.99
    if "perl" in cmd_l:
        return "Perl", 0.99
    if cmd_l in {"sh", "bash", "dash", "ksh", "zsh"}:
        return "Shell", 0.99
    if cmd_l == "node" or cmd_l == "nodejs":
        return "JavaScript", 0.98
    if cmd_l == "ruby":
        return "Ruby", 0.98
    if cmd_l == "php":
        return "PHP", 0.98
    if cmd_l == "lua":
        return "Lua", 0.98
    return "Other", 0.60


def _scan_tokens(path: str, tokens: list[bytes], limit_bytes: int = 64 * 1024 * 1024) -> dict[bytes, bool]:
    found = {t: False for t in tokens}
    max_tok = max((len(t) for t in tokens), default=0)
    tail = b""
    total = 0
    with open(path, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > limit_bytes:
                break
            buf = tail + chunk
            for t in tokens:
                if not found[t] and t in buf:
                    found[t] = True
            tail = buf[-max_tok:] if max_tok else b""
            if all(found.values()):
                break
    return found


def classify_elf(path: str, tools: ToolRunner, use_ldd: bool, use_strings_tool: bool) -> list[Candidate]:
    evs: list[Evidence] = [Evidence("magic", "ELF", 0.5, "python")]
    # Prefer readelf for metadata and DT_NEEDED (avoid ldd risk by default).
    sections = set()
    needed = set()
    dynsym = set()

    re_sec = tools.run(["readelf", "-W", "-S", path], timeout_s=10.0)
    if re_sec.ok:
        for line in re_sec.stdout.splitlines():
            if "]" in line and "." in line:
                # crude: extract section name between ] and next whitespace
                # Example: [ 1] .interp ...
                parts = line.split()
                if len(parts) >= 2 and parts[1].startswith("."):
                    sections.add(parts[1])
        if sections:
            evs.append(Evidence("elf_section", f"sections: {sorted(list(sections))[:12]}{'...' if len(sections)>12 else ''}", 0.3, "readelf"))
    else:
        evs.append(Evidence("tool", "readelf -S unavailable/failed", 0.0, "readelf"))

    re_dyn = tools.run(["readelf", "-d", path], timeout_s=10.0)
    if re_dyn.ok:
        for line in re_dyn.stdout.splitlines():
            if "(NEEDED)" in line:
                # ... Shared library: [libc.so.6]
                lb = line.find("[")
                rb = line.find("]", lb + 1)
                if lb != -1 and rb != -1:
                    needed.add(line[lb + 1:rb])
        if needed:
            evs.append(Evidence("elf_needed", f"DT_NEEDED: {sorted(list(needed))}", 0.4, "readelf"))
    else:
        evs.append(Evidence("tool", "readelf -d unavailable/failed", 0.0, "readelf"))

    # dyn symbols via nm -D
    nm = tools.run(["nm", "-D", path], timeout_s=10.0)
    if nm.ok:
        for line in nm.stdout.splitlines():
            parts = line.strip().split()
            if parts:
                name = parts[-1]
                if name and all(c.isprintable() for c in name):
                    dynsym.add(name)
        if dynsym:
            evs.append(Evidence("elf_symbol", f"nm -D symbols: {len(dynsym)}", 0.3, "nm"))
    else:
        # fallback: readelf dynsyms
        re_syms = tools.run(["readelf", "-Ws", "--dyn-syms", path], timeout_s=10.0)
        if re_syms.ok:
            for line in re_syms.stdout.splitlines():
                if ":" in line:
                    continue
                parts = line.split()
                if parts:
                    name = parts[-1]
                    if name and name != "UND":
                        dynsym.add(name)
            if dynsym:
                evs.append(Evidence("elf_symbol", f"readelf --dyn-syms symbols: {len(dynsym)}", 0.25, "readelf"))

    # Optional ldd (disabled by default; may execute the binary).
    if use_ldd:
        ldd = tools.run(["ldd", path], timeout_s=10.0)
        if ldd.ok:
            evs.append(Evidence("ldd", "ldd run (enabled by user)", 0.1, "ldd"))
        else:
            evs.append(Evidence("ldd", f"ldd failed: {ldd.stderr.strip()}", 0.0, "ldd"))

    # Raw token scan (pure python) – robust even when stripped.
    tokens = {
        # Go
        b"\xff Go buildinf:": ("Go", 1.2, "go buildinfo magic"),
        b".go.buildinfo": ("Go", 0.8, "go buildinfo section name string"),
        b".note.go.buildid": ("Go", 0.7, "go buildid section name string"),
        b"Go build ID": ("Go", 0.7, "go build id marker"),
        # Rust
        b"rust_eh_personality": ("Rust", 1.0, "rust EH personality"),
        b"rust_begin_unwind": ("Rust", 0.9, "rust panic entry"),
        b"rust_begin_panic": ("Rust", 0.8, "rust panic entry (legacy)"),
        b"__rust_alloc": ("Rust", 0.8, "rust allocator symbol"),
        # C++
        b"__gxx_personality_v0": ("C++", 1.0, "c++ EH personality"),
        b"GLIBCXX_": ("C++", 0.6, "libstdc++ symbol versions"),
        b"CXXABI_": ("C++", 0.6, "c++ ABI symbol versions"),
        b"libstdc++.so.6": ("C++", 0.9, "links libstdc++"),
        b"libc++.so.1": ("C++", 0.9, "links libc++"),
    }

    found = _scan_tokens(path, list(tokens.keys()))
    for t, ok in found.items():
        if ok:
            lang, w, desc = tokens[t]
            evs.append(Evidence("token", f"{desc} ({t[:32]!r})", w, "python_scan"))

    # Mangling-based evidence:
    # Rust v0: symbols start with _R (rustc docs)
    rust_v0 = any(s.startswith("_R") for s in dynsym)
    if rust_v0:
        evs.append(Evidence("elf_symbol", "Rust v0 mangling prefix _R observed", 1.2, "nm/readelf"))

    # C++ Itanium: symbols start with _Z (but overlaps with Rust legacy; therefore Rust is checked first in scoring).
    cpp_itanium = any(s.startswith("_Z") for s in dynsym)
    if cpp_itanium:
        evs.append(Evidence("elf_symbol", "Itanium-style mangling prefix _Z observed", 0.9, "nm/readelf"))

    # Section-based evidence for Go:
    if ".go.buildinfo" in sections:
        evs.append(Evidence("elf_section", "section .go.buildinfo present", 1.2, "readelf"))
    if ".note.go.buildid" in sections:
        evs.append(Evidence("elf_section", "section .note.go.buildid present", 0.9, "readelf"))

    # Candidate scoring with precedence encoded by weights and later selection logic.
    scores = defaultdict(float)
    lang_evs: dict[Language, list[Evidence]] = defaultdict(list)

    def add(lang: Language, evidence: Evidence) -> None:
        scores[lang] += evidence.weight
        lang_evs[lang].append(evidence)

    # Distribute evidence to candidates
    for ev in evs:
        # Always attach core evidence later; candidate-specific evidence added below.
        pass

    # Go evidence
    for ev in evs:
        if ("go build" in ev.value.lower()) or (".go.buildinfo" in ev.value) or (".note.go.buildid" in ev.value):
            add("Go", ev)

    # Rust evidence
    for ev in evs:
        if ("rust" in ev.value.lower()) or ("_r" in ev.value.lower()):
            add("Rust", ev)

    # C++ evidence
    for ev in evs:
        if ("c++" in ev.value.lower()) or ("gxx_personality" in ev.value) or ("libstdc++" in ev.value) or ("glibcxx_" in ev.value.lower()) or ("cxxabi_" in ev.value.lower()):
            add("C++", ev)
        elif ev.kind == "elf_symbol" and "prefix _Z" in ev.value:
            add("C++", ev)

    # C fallback: modest score if ELF but no strong signals
    add("C", Evidence("heuristic", "ELF executable/library with no stronger language markers", 0.6, "python"))

    # Attach generic ELF evidence to all candidates (for transparency, not scoring).
    generic = [e for e in evs if e.kind in {"magic", "elf_section", "elf_needed", "elf_symbol", "tool"}]
    for lang in list(scores.keys()):
        lang_evs[lang].extend([Evidence(e.kind, e.value, 0.0, e.via) for e in generic])

    # Important precedence guard: if Rust has strong signal, reduce C++ score from _Z-only overlap.
    if scores["Rust"] >= 1.0 and scores["C++"] <= 0.9:
        scores["C++"] *= 0.5

    cands = [Candidate(lang=k, score=v, evidence=lang_evs[k]) for k, v in scores.items()]
    return cands


def classify_text_no_shebang(path: str, prefix: bytes) -> list[Candidate]:
    text = prefix.decode("utf-8", errors="ignore")
    cands: list[Candidate] = []

    def cand(lang: Language, score: float, ev: str) -> None:
        cands.append(Candidate(lang, score, [Evidence("text_heuristic", ev, score, "python")]))

    # Quick recognisers
    if "<?php" in text:
        cand("PHP", 1.2, "found '<?php' opening tag")
    if "use strict" in text or "use warnings" in text:
        cand("Perl", 0.9, "found typical Perl pragmas")
    if "import " in text or "def " in text or "__name__" in text:
        cand("Python", 0.8, "found typical Python tokens")
    if "require(" in text or "module.exports" in text:
        cand("JavaScript", 0.8, "found typical CommonJS tokens")
    if "set -e" in text or "case " in text or "fi\n" in text or "then\n" in text:
        cand("Shell", 0.6, "found typical shell tokens")

    if not cands:
        cands.append(Candidate("Other", 0.2, [Evidence("text_heuristic", "text file without shebang; unknown language", 0.2, "python")]))
    return cands

