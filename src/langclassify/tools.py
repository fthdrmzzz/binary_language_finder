from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from typing import Sequence


@dataclass(frozen=True)
class ToolResult:
    ok: bool
    stdout: str
    stderr: str
    exit_code: int


class ToolRunner:
    def __init__(self) -> None:
        self.cache: dict[str, str | None] = {}

    def which(self, name: str) -> str | None:
        if name not in self.cache:
            self.cache[name] = shutil.which(name)
        return self.cache[name]

    def run(self, argv: Sequence[str], timeout_s: float = 10.0) -> ToolResult:
        exe = argv[0]
        if self.which(exe) is None:
            return ToolResult(ok=False, stdout="", stderr=f"missing tool: {exe}", exit_code=127)
        try:
            cp = subprocess.run(
                list(argv),
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout_s,
            )
            return ToolResult(ok=(cp.returncode == 0), stdout=cp.stdout, stderr=cp.stderr, exit_code=cp.returncode)
        except subprocess.TimeoutExpired:
            return ToolResult(ok=False, stdout="", stderr=f"timeout running: {' '.join(argv)}", exit_code=124)
        except Exception as e:  # defensive
            return ToolResult(ok=False, stdout="", stderr=f"error running {' '.join(argv)}: {e!r}", exit_code=1)

