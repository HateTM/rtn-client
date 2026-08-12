# NetProbe

A portable Windows GUI tool for network discovery (IP, gateway, neighbors) and IPv4 configuration, built with Python/Tkinter.

## Key Facts
- **Entrypoint:** `netprobe.py`
- **Build System:** `build.bat` (uses `PyInstaller`).
- **Dependencies:** `scapy` (managed in `requirements.txt`).
- **Privileges:** Designed to run **without** Administrator privileges for most tasks. Administrative rights are required *only* for promisc-mode (SIO_RCVALL), manual IP assignment, and full Npcap L2 functionality.
- **Npcap:** An optional, system-level dependency. Do not try to package it; if present, the tool detects and utilizes it automatically.

## Operational Workflow
1. **Development:** Edit `netprobe.py`.
2. **Testing (Headless):** Use `selftest.py` to verify engine logic (ARP scan, passive discovery) without launching the GUI.
3. **Build:** Run `build.bat` from a Windows CLI. This produces two binaries in `dist/`:
   - `NetProbe.exe`: Portable, zero-dependency, basic functionality.
   - `NetProbe-Npcap.exe`: Portable + full L2 support if Npcap is installed on the host.

## Technical Gotchas
- **Windows Portability:** The engine heavily uses `ctypes` to call `iphlpapi` and `shell32`, avoiding external driver dependencies where possible.
- **WebLCT Integration:**
    - Requires `plink.exe` (PuTTY) for SSH-based configuration backup.
    - Manipulates Edge browser profiles (`WebLCT_EdgeProfile`) to implement autologin via extension injection (`--load-extension`).
- **No UAC:** The app intentionally lacks a UAC manifest so it starts on restricted user accounts.
- **Firewall:** Windows Firewall may block incoming UDP, reducing the effectiveness of the passive discovery phase.
- **Interface Naming:** `netsh` operations are executed by FriendlyName; fallback to index is implemented to handle localized OS interface names.
