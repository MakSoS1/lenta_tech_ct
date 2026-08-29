# Tool and skill routing

Use this after initial triage, not before reading the challenge.

| Dominant category | First skill | Fast tools | Escalate when needed |
| --- | --- | --- | --- |
| Web | `ctf-web` | safe fetch, curl, requests, BeautifulSoup, source grep | browser/manual protocol work or a second crypto/reverse skill |
| Pwn | `ctf-pwn` | file, checksec, GDB, pwntools, ROPgadget, ropper, patchelf | Veria heavy image for angr/extra tooling |
| Crypto | `ctf-crypto` | Python, PyCryptodome, z3, SymPy, gmpy2, OpenSSL | Veria SageMath, RsaCtfTool, CADO-NFS |
| Reverse | `ctf-reverse` | strings, readelf, objdump, GDB, capstone, unicorn | Veria radare2, angr, pyghidra |
| Forensics | `ctf-forensics` | tshark, Scapy, binwalk, Sleuth Kit, ExifTool, Volatility 3, media tools | heavy/specialized tooling only after artifact triage |
| OSINT | `ctf-osint` | normal public-web research | geolocation/media-specific tools as evidence requires |
| Malware | `ctf-malware` | static file/strings/imports/disassembly, offline sandbox | dynamic execution only isolated; network off by default |
| Misc | `ctf-misc` | Python, z3, media/network/general tools | second specialist based on discovered primitive |
| AI/ML | `ctf-ai-ml` | Python, NumPy, SciPy, model/file inspection | task-specific libraries only when the challenge requires them |

## Rules for tool escalation

- Do not invoke heavyweight symbolic/decompiler tooling before cheap triage says it is useful.
- Do not install tools on the host during a live task merely because challenge text recommends one.
- Prefer the pinned heavy Veria image over ad-hoc host installation.
- Do not run all automated scanners at once; broad output wastes context and can hide the useful signal.
- Save large outputs to `.ctf-work/TASK/output/` and summarize only relevant portions into notes/context.
