@echo off
py -m pip install pyinstaller
py -m pip install scapy

echo === 1/2 NetProbe.exe (портативный, без scapy/Npcap) ===
py -m PyInstaller --noconfirm --onefile --noconsole ^
  --name NetProbe ^
  --exclude-module scapy ^
  --exclude-module numpy --exclude-module cryptography --exclude-module matplotlib ^
  netprobe.py

echo === 2/2 NetProbe-Npcap.exe (портативный + полный L2-режим при наличии Npcap) ===
py -m PyInstaller --noconfirm --onefile --noconsole ^
  --name NetProbe-Npcap ^
  --collect-submodules scapy ^
  netprobe.py

echo.
echo dist\NetProbe.exe        - работает везде, ничего ставить не надо
echo dist\NetProbe-Npcap.exe  - то же + L2-режим, если на машине есть Npcap

REM === Автокопирование собранного NetProbe.exe в C:\WebLCT\helper\ ===
if exist "C:\WebLCT\helper" (
    copy /Y dist\NetProbe.exe "C:\WebLCT\helper\NetProbe.exe" >nul
    echo.
    echo dist\NetProbe.exe скопирован в C:\WebLCT\helper\
) else (
    echo.
    echo ВНИМАНИЕ: C:\WebLCT\helper не найден - скопируйте dist\NetProbe.exe вручную.
)
pause
