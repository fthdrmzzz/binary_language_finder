from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from langclassify.detectors import classify_path
from langclassify.tools import ToolRunner


def _write(p: Path, data: bytes) -> None:
    p.write_bytes(data)
    p.chmod(0o755)


def _have(cmd: str) -> bool:
    return shutil.which(cmd) is not None


@pytest.fixture()
def tools() -> ToolRunner:
    return ToolRunner()


def test_shebang_python(tmp_path: Path, tools: ToolRunner) -> None:
    p = tmp_path / "a.py"
    _write(p, b"#!/usr/bin/env python3\nprint('hi')\n")
    r = classify_path(str(p), tools)
    assert r.language == "Python"
    assert r.confidence > 0.9
    assert any(e.kind == "shebang" for e in r.evidence)


def test_shebang_perl(tmp_path: Path, tools: ToolRunner) -> None:
    p = tmp_path / "a.pl"
    _write(p, b"#!/usr/bin/perl\nprint \"hi\\n\";\n")
    r = classify_path(str(p), tools)
    assert r.language == "Perl"


def test_shebang_shell(tmp_path: Path, tools: ToolRunner) -> None:
    p = tmp_path / "a.sh"
    _write(p, b"#!/bin/sh\necho hi\n")
    r = classify_path(str(p), tools)
    assert r.language == "Shell"


def test_shebang_node(tmp_path: Path, tools: ToolRunner) -> None:
    p = tmp_path / "a.js"
    _write(p, b"#!/usr/bin/env node\nconsole.log('hi')\n")
    r = classify_path(str(p), tools)
    assert r.language == "JavaScript"


def test_java_class_magic(tmp_path: Path, tools: ToolRunner) -> None:
    p = tmp_path / "Hello.class"
    # Minimal signature; validity of full class structure not required for magic-based detection.
    _write(p, b"\xCA\xFE\xBA\xBE\x00\x00\x00\x34xxxx")
    r = classify_path(str(p), tools)
    assert r.language == "Java"
    assert r.confidence > 0.9


def test_jar_manifest(tmp_path: Path, tools: ToolRunner) -> None:
    import zipfile
    p = tmp_path / "a.jar"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
        zf.writestr("com/example/Hello.class", b"\xCA\xFE\xBA\xBE\x00\x00\x00\x34")
    r = classify_path(str(p), tools)
    assert r.language == "Java"


@pytest.mark.skipif(not _have("gcc"), reason="gcc not installed")
def test_c_binary_and_stripped(tmp_path: Path, tools: ToolRunner) -> None:
    c = tmp_path / "c.c"
    c.write_text("int main(){return 0;}\n", encoding="utf-8")
    out = tmp_path / "cbin"
    subprocess.check_call(["gcc", str(c), "-o", str(out)])
    r = classify_path(str(out), tools)
    assert r.language in {"C", "C++", "Other"}  # allow conservative fallback
    # Now strip symbols (harder case)
    if _have("strip"):
        subprocess.check_call(["strip", str(out)])
        r2 = classify_path(str(out), tools)
        assert r2.language in {"C", "Other"}  # stripping reduces evidence


@pytest.mark.skipif(not _have("g++"), reason="g++ not installed")
def test_cpp_binary(tmp_path: Path, tools: ToolRunner) -> None:
    cpp = tmp_path / "a.cpp"
    cpp.write_text("#include <iostream>\nint main(){std::cout<<\"hi\";}\n", encoding="utf-8")
    out = tmp_path / "cppbin"
    subprocess.check_call(["g++", str(cpp), "-o", str(out)])
    r = classify_path(str(out), tools)
    assert r.language == "C++"


@pytest.mark.skipif(not _have("go"), reason="go not installed")
def test_go_binary(tmp_path: Path, tools: ToolRunner) -> None:
    g = tmp_path / "main.go"
    g.write_text("package main\nfunc main(){}\n", encoding="utf-8")
    out = tmp_path / "gobin"
    subprocess.check_call(["go", "build", "-o", str(out), str(g)])
    r = classify_path(str(out), tools)
    assert r.language == "Go"
    assert r.confidence > 0.7


@pytest.mark.skipif(not _have("rustc"), reason="rustc not installed")
def test_rust_binary(tmp_path: Path, tools: ToolRunner) -> None:
    rs = tmp_path / "main.rs"
    rs.write_text("fn main() {}", encoding="utf-8")
    out = tmp_path / "rustbin"
    subprocess.check_call(["rustc", str(rs), "-o", str(out)])
    r = classify_path(str(out), tools)
    assert r.language in {"Rust", "C++", "Other"}  # depends on symbols/build profile


@pytest.mark.skipif(not _have("mcs"), reason="mono mcs not installed")
def test_dotnet_binary(tmp_path: Path, tools: ToolRunner) -> None:
    cs = tmp_path / "Hello.cs"
    cs.write_text("using System; class Hello{ static void Main(){ } }", encoding="utf-8")
    out = tmp_path / "hello.exe"
    subprocess.check_call(["mcs", "-out:" + str(out), str(cs)])
    r = classify_path(str(out), tools)
    assert r.language == ".NET"

