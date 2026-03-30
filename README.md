#### Overview

This tool performs uses heuristics to identify programming language of binaries. It doesn't provide a guaranteed result, but provides confidence value for user to determine. Initial intention was to have an overall idea about the distribution of binaries in our system.
 
Supported categories:

* C
* C++
* Go
* Rust
* Python
* Perl
* Bash / Shell
* Other (fallback)

The approach is **heuristic-based**. It does not guarantee correctness, especially for stripped or statically linked binaries.

---

#### How it works

1. **File type detection**
   Uses file to separate:

   * scripts (via shebang)
   * ELF binaries

2. **Script detection**
   Based on shebang:

   * `#!/usr/bin/python` → Python
   * `#!/usr/bin/perl` → Perl
   * `#!/bin/bash` / `sh` → Shell

3. **Binary classification (ELF only)**

   Signals used:

   * **C++**

     * `_Z` (mangled symbols)
     * `__gxx_personality`
     * `libstdc++`

   * **Go**

     * `Go build ID`
     * `runtime.*`
     * static linking patterns

   * **Rust**

     * `rust_eh_personality`
     * `core::panicking`
     * `alloc::` / `std::`

   * **C**

     * fallback if no higher-confidence match

4. **Confidence model**
   The tool prioritizes:

   ```
   Script > Go > Rust > C++ > C
   ```

---

#### Installation

No build step required.

Dependencies:

```bash
apt update && apt install -y file binutils
```

Optional (improves detection):

```bash
apt install -y libc-bin
```

---

#### Usage

Basic usage:

```bash
python3 detect_lang.py bin_list.txt
```

Where `bin_list.txt` contains:

```
/usr/bin/ls
/usr/bin/python3
/usr/bin/perl
...
```

---

#### Output

Example:

```
/usr/bin/ls            C
/usr/bin/g++           C++
/usr/bin/go            GO
/usr/bin/rustc         RUST
/usr/bin/python3       PYTHON
/usr/bin/perl          PERL
/usr/bin/bash          SHELL
```

---

#### Output with counts

```
C:      120
C++:     45
Go:      10
Rust:     6
Python:  18
Perl:     7
Shell:   22
Other:    3
```

---

#### Limitations

* Stripped binaries reduce accuracy
* Static binaries may hide language signals
* C is a fallback category (low confidence)
* Mixed-language binaries (e.g. C + C++) may be misclassified
* Some languages (Java, Node.js) appear as launchers, not native binaries

This tool is intended for:

* system-level analysis
* container inspection
* research pipelines (like yours)

Not for:

* precise attribution
* security-critical decisions

---

#### Tests

Run tests:

```bash
python3 -m unittest tests/test_detect.py
```

Test coverage includes:

* script detection (Python, Bash, Perl)
* synthetic binaries with injected symbols
* known system binaries (if available)

---

#### Extending

You can extend detection by adding:

* `.comment` section parsing (`readelf -p .comment`)
* DWARF info (if present)
* linker signature detection
* package metadata correlation (dpkg / rpm)

---

#### Summary

This tool gives a **practical approximation** of binary language composition in a system. It is intentionally simple, transparent, and easy to adapt for research workflows.

