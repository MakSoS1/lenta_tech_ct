# CTF toolbox layers

Use the smallest layer that can answer the current hypothesis.

## Fast image: `lenta-ctf-fast`

Intended for the first pass and most challenge work. It contains:

- binary/pwn: GDB, multiarch GDB, binutils, readelf/objdump, checksec, patchelf, ltrace/strace, pwntools, capstone, unicorn, ROPgadget and ropper;
- web/network: curl, wget, netcat, nmap, tcpdump, tshark, DNS tools, requests and BeautifulSoup;
- crypto/constraints: OpenSSL, PyCryptodome, z3, SymPy and gmpy2;
- forensics/stego: binwalk, Sleuth Kit, foremost, ExifTool, steghide, pngcheck, ImageMagick, ffmpeg, sox, Tesseract, Volatility 3 and Scapy;
- general: Python, compiler toolchain, CMake, jq, ripgrep, SQLite, archive utilities, NumPy and SciPy.

Build and smoke-test it with `./scripts/build_images.sh fast`.

## Heavy image: pinned Veria `ctf-sandbox`

Use `./scripts/build_images.sh veria` when the task needs heavyweight components such as SageMath, angr, pyghidra, RsaCtfTool, CADO-NFS, radare2 or the broader Veria toolset. The build uses `sandbox/Dockerfile.sandbox` directly from the exact pinned `verialabs/ctf-agent` commit; this repository does not rewrite that Dockerfile.

The heavy build is intentionally not part of every local preflight because it is large. GitHub Actions exposes it as an explicit manual option.

## Isolation

Launch a private task with `./scripts/run_sandbox.sh TASK`. Networking is off by default. Add `--network` only for an organizer/user-supplied official target. Add `--debug` only when ptrace is required for GDB. Neither mode mounts the host home directory or Docker socket.
