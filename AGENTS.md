# NetProbe and RTN Client AGENTS.md

This repository contains two primary components:
1. **NetProbe**: Windows GUI network tool.
2. **RTN Client**: FastAPI service for WebLCT/RTN.

## Critical Instructions for Agents

### Entrypoints
- **GUI**: `netprobe.py`
- **API**: `rtn_client.py` (FastAPI)

### Build & Workflow
- **Packaging**: Use `build.bat` (PyInstaller). Output: `dist/`.
- **Workflow**: Ensure syntax/lint checks (`py_compile`, `ruff`) pass before commits.

### RTN Client (WebLCT) Integration
- **Headers**: Must include `User-Agent`, `Referer`, `Origin`. Keep session alive via `CookieJar`.
- **Troubleshooting**: `HTTP 500`/`405` are common. Use debug logs for headers/bodies to diagnose.
- **Reset**: Perform `TSLogoutServlet` call to reset sessions if API calls fail.

### Windows Platform & Gotchas
- **Privileges**: "No UAC" design. Do NOT request admin rights unless absolutely required (Npcap, `netsh`).
- **Interface Naming**: Use `FriendlyName`, fallback to index for `netsh` compatibility.
- **Npcap**: Optional/detected, never attempt to package.
