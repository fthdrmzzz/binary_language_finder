from __future__ import annotations

import io
import os
import struct
import zipfile
from typing import Iterable


ELF_MAGIC = b"\x7fELF"
JAVA_CLASS_MAGIC = b"\xCA\xFE\xBA\xBE"
ZIP_MAGIC = b"PK\x03\x04"
MZ_MAGIC = b"MZ"


def read_prefix(path: str, n: int = 8192) -> bytes:
    with open(path, "rb") as f:
        return f.read(n)


def read_first_line_bytes(path: str, max_len: int = 4096) -> bytes:
    with open(path, "rb") as f:
        return f.readline(max_len)


def is_probably_text(prefix: bytes) -> bool:
    if not prefix:
        return False
    if b"\x00" in prefix:
        return False
    # Heuristic: high ASCII/control density suggests binary.
    bad = 0
    for b in prefix:
        if b in (9, 10, 13):  # tab/newline/cr
            continue
        if 32 <= b <= 126:
            continue
        bad += 1
    return (bad / len(prefix)) < 0.05


def parse_shebang(line: bytes) -> tuple[str, str | None] | None:
    # Accept '#!' then strip whitespace.
    if not line.startswith(b"#!"):
        return None
    text = line[2:].strip().decode("utf-8", errors="replace")
    if not text:
        return None
    # execve(2) allows '#!interpreter [optional-arg]' (single optional arg).
    parts = text.split()
    interp = parts[0]
    opt = parts[1] if len(parts) > 1 else None
    return interp, opt


def iter_zip_names(path: str) -> Iterable[str]:
    # Safe: zipfile reads central directory; will raise on malformed input.
    with zipfile.ZipFile(path, "r") as zf:
        for n in zf.namelist():
            yield n


def is_jar(path: str) -> bool:
    # Oracle: a JAR is essentially a ZIP that can include META-INF/MANIFEST.MF.
    # We treat manifest presence OR any .class file as strong Java signals.
    names = list(iter_zip_names(path))
    lower = [n.lower() for n in names]
    if "meta-inf/manifest.mf" in lower:
        return True
    if any(n.endswith(".class") for n in lower):
        return True
    return False


class PEInfo:
    def __init__(self) -> None:
        self.is_pe: bool = False
        self.is_dotnet: bool = False
        self.errors: list[str] = []
        self.machine: int | None = None
        self.pe_magic: int | None = None             # 0x10b or 0x20b
        self.com_descriptor_rva: int | None = None
        self.com_descriptor_size: int | None = None
        self.bs_jb_found: bool = False


def _rva_to_file_offset(sections: list[tuple[int, int, int, int]], rva: int) -> int | None:
    # sections: (va, vsize, raw_ptr, raw_size)
    for va, vsize, raw_ptr, raw_size in sections:
        max_size = max(vsize, raw_size)
        if va <= rva < va + max_size:
            return raw_ptr + (rva - va)
    return None


def parse_pe_for_dotnet(path: str) -> PEInfo:
    """
    Minimal PE parser:
      - Validate MZ and PE\0\0 via e_lfanew
      - Read IMAGE_FILE_HEADER, optional header, section headers
      - Check DataDirectory[14] (COM descriptor / CLR header)
      - If present, map RVA to file offset, parse IMAGE_COR20_HEADER metadata RVA
      - Confirm metadata root 'BSJB'
    """
    info = PEInfo()
    try:
        with open(path, "rb") as f:
            dos = f.read(64)
            if len(dos) < 64 or not dos.startswith(MZ_MAGIC):
                return info
            e_lfanew = struct.unpack_from("<I", dos, 0x3C)[0]
            f.seek(e_lfanew)
            sig = f.read(4)
            if sig != b"PE\x00\x00":
                return info
            info.is_pe = True

            file_hdr = f.read(20)
            if len(file_hdr) < 20:
                info.errors.append("short IMAGE_FILE_HEADER")
                return info
            info.machine = struct.unpack_from("<H", file_hdr, 0)[0]
            number_of_sections = struct.unpack_from("<H", file_hdr, 2)[0]
            size_of_optional_header = struct.unpack_from("<H", file_hdr, 16)[0]

            opt = f.read(size_of_optional_header)
            if len(opt) < 2:
                info.errors.append("short optional header")
                return info
            info.pe_magic = struct.unpack_from("<H", opt, 0)[0]
            if info.pe_magic == 0x10B:       # PE32
                data_dir_offset = 96
            elif info.pe_magic == 0x20B:     # PE32+
                data_dir_offset = 112
            else:
                info.errors.append(f"unknown optional header magic: {info.pe_magic:#x}")
                return info

            if len(opt) < data_dir_offset + 8 * 15:
                info.errors.append("optional header too short for data directories")
                return info

            # DataDirectory[14] is COM descriptor table (CLR runtime header) in winnt.h docs.
            entry14_off = data_dir_offset + 8 * 14
            com_rva, com_size = struct.unpack_from("<II", opt, entry14_off)
            info.com_descriptor_rva = com_rva
            info.com_descriptor_size = com_size

            if com_rva == 0 or com_size == 0:
                return info  # PE but not clearly managed

            # Parse section headers (40 bytes each) to allow RVA mapping.
            sections: list[tuple[int, int, int, int]] = []
            for _ in range(number_of_sections):
                sh = f.read(40)
                if len(sh) < 40:
                    info.errors.append("short section header table")
                    break
                virtual_size = struct.unpack_from("<I", sh, 8)[0]
                virtual_address = struct.unpack_from("<I", sh, 12)[0]
                size_of_raw_data = struct.unpack_from("<I", sh, 16)[0]
                ptr_to_raw = struct.unpack_from("<I", sh, 20)[0]
                sections.append((virtual_address, virtual_size, ptr_to_raw, size_of_raw_data))

            cor_off = _rva_to_file_offset(sections, com_rva)
            if cor_off is None:
                info.errors.append("could not map CLR header RVA to file offset")
                # still treat as likely .NET because COM descriptor exists
                info.is_dotnet = True
                return info

            f.seek(cor_off)
            cor = f.read(0x48)  # IMAGE_COR20_HEADER is typically 0x48 bytes
            if len(cor) < 0x18:
                info.errors.append("short CLR header")
                info.is_dotnet = True
                return info

            cb = struct.unpack_from("<I", cor, 0)[0]
            # metadata IMAGE_DATA_DIRECTORY at offset 8
            md_rva, md_size = struct.unpack_from("<II", cor, 8)
            md_off = _rva_to_file_offset(sections, md_rva)
            if md_off is None:
                info.errors.append("could not map metadata RVA to file offset")
                info.is_dotnet = True
                return info

            f.seek(md_off)
            md_sig = f.read(4)
            if md_sig == b"BSJB":
                info.bs_jb_found = True
                info.is_dotnet = True
            else:
                # Still likely .NET due to CLR header presence, but weaker without signature.
                info.is_dotnet = True
            # record cb for debugging if desired
            if cb == 0:
                info.errors.append("CLR header cb=0 (unexpected)")
            return info
    except OSError as e:
        info.errors.append(f"os error: {e}")
        return info

