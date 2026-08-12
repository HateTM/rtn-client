import ctypes
import ipaddress
import os
import queue
import re
import socket
import struct
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

import tkinter as tk
from tkinter import ttk, filedialog, messagebox

SCAPY_ERR = None
try:
    from scapy.all import conf, sniff, srp, get_if_hwaddr, Ether, ARP, IP, UDP, ICMP
    conf.verb = 0
    SCAPY = True
except Exception as e:
    SCAPY = False
    SCAPY_ERR = repr(e)

BCAST_MAC = "ff:ff:ff:ff:ff:ff"
NO_WIN = 0x08000000
LISTEN_PORTS = [68, 67, 137, 138, 1900, 5353, 5355, 3702, 5678]
SSDP_MSEARCH = (
    b'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n'
    b'MAN: "ssdp:discover"\r\nMX: 2\r\nST: upnp:rootdevice\r\n\r\n'
)


def has_npcap():
    for p in (r"C:\Windows\System32\Npcap\wpcap.dll", r"C:\Windows\System32\wpcap.dll"):
        if os.path.exists(p):
            return True
    return False


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_admin():
    try:
        exe = sys.executable
        params = " ".join(f'"{a}"' for a in sys.argv[1:])
        if not getattr(sys, "frozen", False):
            params = f'"{os.path.abspath(sys.argv[0])}" {params}'
        return ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1) > 32
    except Exception:
        return False


def run_cmd(args):
    try:
        p = subprocess.run(args, capture_output=True, creationflags=NO_WIN)
    except Exception as e:
        return 1, repr(e)
    blob = p.stdout + p.stderr
    # Декодируем вывод Windows-утилит. Пробуем строго: utf-8 -> cp866 (OEM, для
    # netsh/ipconfig/arp в русской Windows) -> cp1251. Это даёт корректную
    # кириллицу вместо "абракадабры" в логе.
    for enc in ("utf-8", "cp866", "cp1251"):
        try:
            return p.returncode, blob.decode(enc, errors="strict").strip()
        except UnicodeDecodeError:
            continue
    # Если ни одна не подошла строго — cp866 с заменой бракованных байтов
    return p.returncode, blob.decode("cp866", errors="replace").strip()


# ---------------------------------------------------------------- WebLCT control
WEBLCT_PORT = 13443
# config-файл рядом с NetProbe.exe (или netprobe.py): хранит путь к WebLCT.
def _weblct_cfg_path():
    base = os.path.dirname(sys.executable) if getattr(sys, "frozen", False) else os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, "netprobe-weblct.txt")


def get_weblct_root(log=None):
    """Возвращает путь к WebLCT (каталог со startweblct.bat).
    Берёт из netprobe-weblct.txt; если нет/невалиден — ищет стандартные места;
    если не находит — возвращает None (вызывающий код спросит пользователя)."""
    # 1. Из сохранённого config-файла
    cfg = _weblct_cfg_path()
    if os.path.exists(cfg):
        try:
            with open(cfg, "r", encoding="utf-8") as fh:
                root = fh.read().strip()
            if root and os.path.exists(os.path.join(root, "startweblct.bat")):
                return root
        except Exception:
            pass
    # 1.5. Родительский каталог exe (NetProbe в <WebLCT>\helper\ → WebLCT в <WebLCT>\)
    base = os.path.dirname(sys.executable) if getattr(sys, "frozen", False) else os.path.dirname(os.path.abspath(__file__))
    parent = os.path.dirname(base)
    if os.path.exists(os.path.join(parent, "startweblct.bat")):
        try:
            with open(cfg, "w", encoding="utf-8") as fh:
                fh.write(parent)
        except Exception:
            pass
        return parent
    # 2. Стандартные места
    for cand in (r"C:\WebLCT", r"D:\WebLCT", r"E:\WebLCT_V100R022", r"E:\WebLCT"):
        if os.path.exists(os.path.join(cand, "startweblct.bat")):
            try:
                with open(cfg, "w", encoding="utf-8") as fh:
                    fh.write(cand)
            except Exception:
                pass
            return cand
    return None


def set_weblct_root(root):
    """Сохраняет путь к WebLCT в config-файл."""
    cfg = _weblct_cfg_path()
    try:
        with open(cfg, "w", encoding="utf-8") as fh:
            fh.write(root)
    except Exception:
        pass


def weblct_running():
    """True, если порт WebLCT (13443) слушается."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        r = s.connect_ex(("127.0.0.1", WEBLCT_PORT))
        s.close()
        return r == 0
    except Exception:
        return False


def weblct_ready(timeout=5):
    """True, если приложение WebLCT готово принимать запросы.
    Отличается от weblct_running(): TCP-порт может слушать раньше,
    чем Spring/OSGi/Hibernate инициализируются. Проверяем реальный
    HTTP-ответ от login.html (200 + тело > 1 КБ)."""
    import urllib.request
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(f"https://localhost:{WEBLCT_PORT}/weblct/page/login.html")
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            body = r.read()
            return r.status == 200 and len(body) > 1000
    except Exception:
        return False


def _find_javaw_pids():
    """Список PID процессов javaw.exe, запущенных из каталога WebLCT (если он известен)."""
    rc, out = run_cmd(["wmic", "process", "where", "name='javaw.exe'",
                       "get", "ProcessId,ExecutablePath", "/format:csv"])
    pids = []
    for line in out.splitlines():
        line = line.strip()
        if not line or "ProcessId" in line:
            continue
        parts = line.split(",")
        # формат: Node,ExecutablePath,ProcessId
        if len(parts) >= 3:
            pid = parts[-1].strip()
            exe = parts[-2].strip()
            if pid.isdigit():
                pids.append((pid, exe))
    return pids


def stop_weblct(root, log=None):
    """Останавливает WebLCT: сначала штатно stopweblct.bat, затем kill зависших javaw."""
    if log:
        log(f"[WebLCT] остановка ({root}\\stopweblct.bat)...")
    stop_bat = os.path.join(root, "stopweblct.bat")
    if os.path.exists(stop_bat):
        # stopweblct.bat интерактивный (pause в конце) — запускаем и не ждём его возврата
        try:
            subprocess.Popen(["cmd", "/c", stop_bat], creationflags=NO_WIN)
        except Exception as e:
            if log:
                log(f"[WebLCT] не запустить stopweblct.bat: {e}")
    # Ждём, пока порт освободится
    for _ in range(15):
        if not weblct_running():
            break
        time.sleep(1)
    # Если порт ещё слушается — kill процессов javaw из каталога WebLCT
    if weblct_running():
        if log:
            log("[WebLCT] порт ещё занят — завершаю процессы javaw.exe из каталога WebLCT...")
        for pid, exe in _find_javaw_pids():
            if root and root.lower() in exe.lower():
                run_cmd(["taskkill", "/F", "/PID", pid])
                if log:
                    log(f"[WebLCT] taskkill /F /PID {pid} ({os.path.basename(exe)})")
        for _ in range(5):
            if not weblct_running():
                break
            time.sleep(1)
    ok = not weblct_running()
    if log:
        log(f"[WebLCT] {'остановлен' if ok else 'НЕ удалось остановить'}")
    return ok


def start_weblct(root, language="1", log=None):
    """Запускает WebLCT: startweblct.bat в отдельном окне, подставляя выбор языка.
    language: '1'=English, '2'=Chinese."""
    start_bat = os.path.join(root, "startweblct.bat")
    if not os.path.exists(start_bat):
        if log:
            log(f"[WebLCT] не найден startweblct.bat в {root}")
        return False
    if weblct_running():
        if log:
            log("[WebLCT] уже запущен — пропуск старта")
        return True
    if log:
        log(f"[WebLCT] запуск startweblct.bat (язык={language})...")
    # startweblct.bat заканчивается "exit" (без /b) и ждёт choice языка.
    # Подать выбор языка через stdin-редирект: PowerShell Start-Process с
    # -RedirectStandardInput честно передаёт stdin в choice(). pipe/call
    # внутри cmd НЕ работает (call — внутренняя команда, pipe до неё не доходит).
    # ВАЖНО: рабочий каталог должен быть root (startweblct.bat использует %cd%).
    tmp_dir = os.environ.get("TEMP", ".")
    lang_file = os.path.join(tmp_dir, f"_weblct_lang_{os.getpid()}.txt")
    try:
        with open(lang_file, "w") as fh:
            fh.write(f"{language}\r\n")
    except Exception as e:
        if log:
            log(f"[WebLCT] не создать lang-файл: {e}")
        return False
    # Запуск через PowerShell — он корректно работает с путями Windows и stdin.
    ps_cmd = (
        f"Start-Process -FilePath 'cmd.exe' -ArgumentList '/c','\"{start_bat}\"' "
        f"-RedirectStandardInput '{lang_file}' -WindowStyle Minimized "
        f"-WorkingDirectory '{root}'"
    )
    try:
        subprocess.Popen(["powershell", "-NoProfile", "-Command", ps_cmd],
                         cwd=root, creationflags=NO_WIN)
    except Exception as e:
        if log:
            log(f"[WebLCT] не запустить: {e}")
        return False
    # Ждём подъёма порта (до ~120 сек)
    if log:
        log("[WebLCT] ожидаю подъёма Tomcat (порт 13443)...")
    for i in range(60):
        if weblct_running():
            if log:
                log(f"[WebLCT] порт открыт (~{i*2} сек)")
            break
        time.sleep(2)
    else:
        if log:
            log("[WebLCT] Tomcat не поднялся за 2 минуты")
        return False
    # Ждём ГОТОВНОСТИ приложения: порт слушается раньше, чем Spring/OSGi
    # инициализируются. Edge, открытый слишком рано, покажет пустую страницу.
    if log:
        log("[WebLCT] ожидаю готовности приложения (login.html отвечает)...")
    for i in range(60):
        if weblct_ready(timeout=3):
            if log:
                log(f"[WebLCT] приложение готово (~{i*2} сек после порта)")
            break
        time.sleep(2)
    else:
        if log:
            log("[WebLCT] приложение не ответило за 2 минуты — открываю в текущем состоянии")
    # Автологин: обновляем cred.json и открываем Edge напрямую (без launch-weblct.bat,
    # который плодил лишние окна). Расширение само заполнит форму.
    ensure_cred_json(root, log=log)
    if log:
        log("[WebLCT] открываю Edge с автологином...")
    open_weblct_browser(root, log=log)
    # Закрываем лишнее окно браузера, которое открыл startweblct.bat (chrome/index.html).
    # close_weblct_browsers НЕ трогает наш Edge профиля WebLCT_EdgeProfile.
    try:
        time.sleep(3)
        close_weblct_browsers(log=log)
    except Exception:
        pass
    if log:
        log("[WebLCT] === запуск завершён ===")
    return True


def find_edge():
    """Путь к msedge.exe или None."""
    for p in (r"C:\Program Files (Microsoft\Edge\Application\msedge.exe",
              r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
              os.path.join(os.environ.get("LOCALAPPDATA", ""),
                           r"Microsoft\Edge\Application\msedge.exe")):
        if os.path.exists(p):
            return p
    return None


def close_weblct_browsers(log=None):
    """Закрывает ТОЛЬКО лишние окна браузеров, открытые startweblct.bat:
    системный браузер (Chrome/Edge по умолчанию) с URL index.html.
    НЕ трогает наш Edge с профилем WebLCT_EdgeProfile (автологин) и
    НЕ трогает окна с login.html (наш автологин)."""
    killed = []
    try:
        rc, out = run_cmd(["wmic", "process", "where",
                           "name='msedge.exe' or name='chrome.exe'",
                           "get", "ProcessId,CommandLine", "/format:csv"])
    except Exception:
        return killed
    for line in out.splitlines():
        line = line.strip()
        if not line or "ProcessId" in line:
            continue
        parts = line.split(",")
        if len(parts) < 3:
            continue
        node, cmdline, pid = parts[0], parts[1], parts[-1].strip()
        if not pid.isdigit():
            continue
        low = cmdline.lower()
        # ПРОПУСКАЕМ наш Edge с профилем автологина — его не закрываем!
        if "weblct_edgeprofile" in low:
            continue
        # Закрываем только чужие окна с index.html (то, что открыл startweblct.bat)
        # Окна с login.html не трогаем (наш автологин).
        if ("localhost:13443" in low and "index.html" in low) or \
           ("localhost:13443/weblct/page/index" in low):
            run_cmd(["taskkill", "/F", "/PID", pid])
            if log:
                log(f"[WebLCT] закрыто лишнее окно startweblct (PID {pid})")
            killed.append(pid)
    return killed


def reinstall_addon(root, log=None):
    """Переустанавливает расширение автологина в профиль Edge:
    закрывает Edge с профилем WebLCT и открывает заново с --load-extension.
    Расширение должно лежать в <root>\\helper\\autologin-ext."""
    edge = find_edge()
    if not edge:
        if log:
            log("[WebLCT] Microsoft Edge не найден — переустановка невозможна")
        return False
    ext = os.path.join(root, "helper", "autologin-ext")
    if not os.path.exists(os.path.join(ext, "manifest.json")):
        if log:
            log(f"[WebLCT] расширение не найдено: {ext}\\manifest.json")
        return False
    profile = os.path.join(os.environ.get("LOCALAPPDATA", ""), "WebLCT_EdgeProfile")
    if log:
        log("[WebLCT] закрываю Edge профиля WebLCT для переустановки расширения...")
    # Закрываем только Edge с профилем WebLCT
    try:
        rc, out = run_cmd(["wmic", "process", "where", "name='msedge.exe'",
                           "get", "ProcessId,CommandLine", "/format:csv"])
        for line in out.splitlines():
            line = line.strip()
            if not line or "ProcessId" in line:
                continue
            parts = line.split(",")
            if len(parts) >= 3 and "weblct_edgeprofile" in parts[1].lower():
                pid = parts[-1].strip()
                if pid.isdigit():
                    run_cmd(["taskkill", "/F", "/PID", pid])
    except Exception:
        pass
    time.sleep(1)
    if log:
        log("[WebLCT] открываю Edge с --load-extension (расширение зарегистрируется заново)...")
    port = WEBLCT_PORT
    url = f"https://localhost:{port}/weblct/page/login.html"
    args = [edge,
            f"--user-data-dir={profile}",
            f"--load-extension={ext}",
            f"--disable-extensions-except={ext}",
            "--ignore-certificate-errors",
            "--no-first-run", "--no-default-browser-check",
            url]
    try:
        subprocess.Popen(args, creationflags=NO_WIN)
    except Exception as e:
        if log:
            log(f"[WebLCT] не запустить Edge: {e}")
        return False
    if log:
        log("[WebLCT] расширение переустановлено; Edge открыт с автологином")
    return True



def netsh_ipv4(ifd, verb, obj, *rest):
    """name= по FriendlyName, при неудаче — по индексу интерфейса (локализованные имена, кавычки)."""
    rc, out = 1, ""
    for key in (ifd.get("name"), str(ifd.get("index", ""))):
        if not key:
            continue
        rc, out = run_cmd(["netsh", "interface", "ipv4", verb, obj, f"name={key}", *rest])
        if rc == 0:
            return rc, out
    return rc, out


def ip_set_dhcp(ifd):
    rc1, o1 = netsh_ipv4(ifd, "set", "address", "source=dhcp")
    rc2, o2 = netsh_ipv4(ifd, "set", "dnsservers", "source=dhcp")
    return rc1 or rc2, (o1 + "\n" + o2).strip()


def ip_set_static(ifd, ip, mask, gw=None, add=False):
    if add:
        return netsh_ipv4(ifd, "add", "address", ip, mask)
    return netsh_ipv4(ifd, "set", "address", "static", ip, mask, gw if gw else "none")


def ip_del(ifd, ip):
    return netsh_ipv4(ifd, "delete", "address", f"addr={ip}")


def ip_show(ifd):
    return netsh_ipv4(ifd, "show", "addresses")[1]


def ensure_cred_json(root, log=None):
    """Читает WEBLCT_USER/WEBLCT_PASSWORD из <root>\\helper\\config.txt и
    обновляет <root>\\helper\\autologin-ext\\cred.json. Возвращает True при успехе."""
    import json, re
    cfg = os.path.join(root, "helper", "config.txt")
    if not os.path.exists(cfg):
        if log:
            log(f"[WebLCT] не найден config.txt: {cfg}")
        return False
    user, passw = "admin", ""
    try:
        with open(cfg, "r", encoding="utf-8") as fh:
            for line in fh:
                m = re.match(r'^\s*set\s+"WEBLCT_USER=(.+)"\s*$', line)
                if m:
                    user = m.group(1).strip()
                m = re.match(r'^\s*set\s+"WEBLCT_PASSWORD=(.+)"\s*$', line)
                if m:
                    passw = m.group(1).strip()
    except Exception as e:
        if log:
            log(f"[WebLCT] не прочитать config.txt: {e}")
        return False
    if not passw:
        if log:
            log("[WebLCT] в config.txt не задан WEBLCT_PASSWORD")
        return False
    cred = {"username": user, "password": passw}
    out = os.path.join(root, "helper", "autologin-ext", "cred.json")
    try:
        with open(out, "w", encoding="utf-8") as fh:
            json.dump(cred, fh, separators=(",", ":"))
    except Exception as e:
        if log:
            log(f"[WebLCT] не записать cred.json: {e}")
        return False
    if log:
        log(f"[WebLCT] cred.json обновлён (user={user})")
    return True


def open_weblct_browser(root, log=None):
    """Открывает Edge с профилем WebLCT и расширением автологина.
    Не закрывает существующие окна — просто добавляет новое.
    Используется, когда пользователь случайно закрыл браузер."""
    edge = find_edge()
    if not edge:
        if log:
            log("[WebLCT] Microsoft Edge не найден")
        return False
    ext = os.path.join(root, "helper", "autologin-ext")
    profile = os.path.join(os.environ.get("LOCALAPPDATA", ""), "WebLCT_EdgeProfile")
    url = f"https://localhost:{WEBLCT_PORT}/weblct/page/login.html"
    if log:
        log("[WebLCT] открываю Edge с автологином...")
    args = [edge,
            f"--user-data-dir={profile}",
            f"--load-extension={ext}",
            f"--disable-extensions-except={ext}",
            "--ignore-certificate-errors",
            "--no-first-run", "--no-default-browser-check",
            url]
    try:
        subprocess.Popen(args, creationflags=NO_WIN)
    except Exception as e:
        if log:
            log(f"[WebLCT] не открыть Edge: {e}")
        return False
    if log:
        log("[WebLCT] Edge открыт")
    return True


# ---------------------------------------------------------------- RTN access
def read_rtn_credentials(root):
    """Читает первую пару RTN_ACCOUNT_* из config.txt.
    Возвращает (user, password) или (None, None)."""
    cfg = os.path.join(root, "helper", "config.txt")
    if not os.path.exists(cfg):
        return None, None
    try:
        with open(cfg, "r", encoding="utf-8") as fh:
            for line in fh:
                m = re.match(r'^\s*set\s+"RTN_ACCOUNT_\d+=(.+)"\s*$', line)
                if m:
                    parts = m.group(1).strip().split("|", 2)
                    if len(parts) >= 3:
                        return parts[1].strip(), parts[2].strip()
    except Exception:
        pass
    return None, None


def find_plink():
    """Путь к plink.exe (PuTTY) или None."""
    for p in (r"C:\Program Files\PuTTY\plink.exe",
              r"C:\Program Files (x86)\PuTTY\plink.exe",
              os.path.join(os.environ.get("LOCALAPPDATA", ""), r"Programs\PuTTY\plink.exe")):
        if os.path.exists(p):
            return p
    return None


def ssh_exec_plink(ip, user, password, command, timeout=15, log=None):
    """Выполняет команду на RTN через plink.exe (PuTTY).
    Возвращает (returncode, stdout+stderr). None, если plink не найден."""
    plink = find_plink()
    if not plink:
        if log:
            log("[RTN] plink.exe не найден (нужен PuTTY) — автоопрос невозможен")
        return None
    # -batch: не интерактивно; -a -a: авто-принятие ключа хоста
    args = [plink, "-batch", "-pw", password,
            "-P", "22",
            f"{user}@{ip}", command]
    try:
        p = subprocess.run(args, capture_output=True, timeout=timeout, creationflags=NO_WIN)
    except subprocess.TimeoutExpired:
        if log:
            log(f"[RTN] таймаут SSH к {ip}")
        return 124, "TIMEOUT"
    except Exception as e:
        if log:
            log(f"[RTN] ошибка plink: {e}")
        return 1, repr(e)
    blob = p.stdout + p.stderr
    for enc in ("utf-8", "cp866", "cp1251"):
        try:
            return p.returncode, blob.decode(enc, errors="replace").strip()
        except Exception:
            continue
    return p.returncode, repr(blob)


# Команды RTN для автоопределения радио-параметров.
# Ключ — команда, значение — человекочитаемое описание.
RTN_RADIO_COMMANDS = [
    ("display radio", "radio: RSL, частота, модуляция"),
    ("display rfunit", "rfunit: радиоблок, мощность"),
    ("display radio-link-info", "radio-link: статус линка"),
    ("display interface brief", "interfaces: статус интерфейсов"),
    ("display interface", "interfaces: полные"),
    ("display hardware", "hardware: платы"),
    ("display version", "version: версия ПО"),
    ("display current-configuration", "config: полная конфигурация"),
]

# Регулярки для извлечения радио-параметров из вывода (универсальные).
RADIO_PATTERNS = {
    "rsl": re.compile(r"(?:rsl|received[\s_-]?level|rx[\s_-]?level|приём)[^\d-]*(-?\d{1,3}\.?\d*)\s*(dbm)?",
                       re.I),
    "tx_power": re.compile(r"(?:tx[\s_-]?power|transmit[\s_-]?power|мощность)[^\d-]*(-?\d{1,3}\.?\d*)\s*(dbm)?",
                            re.I),
    "modulation": re.compile(r"(?:modulation|модуляция|cur[\s_-]?mod)[^\d]*\b(\d{1,3})\s*([qam]\w*)?", re.I),
    "frequency": re.compile(r"(?:frequency|частота|tx[\s_-]?freq)[^\d]*(\d{3,5}\.?\d*)\s*(mhz|ghz)?", re.I),
}


def probe_rtn_radio(ip, user, password, log=None):
    """Автоопределение радио-параметров RTN: перебирает вероятные команды,
    находит RSL/модуляцию/частоту/мощность через регулярки.
    Возвращает {cmd, rsl, modulation, frequency, tx_power, raw, worked_commands}."""
    result = {"rsl": None, "modulation": None, "frequency": None,
              "tx_power": None, "worked_commands": [], "raw": {}}
    if log:
        log(f"[RTN] автоопрос радио {ip} ({user})...")
    for cmd, desc in RTN_RADIO_COMMANDS:
        rc, out = ssh_exec_plink(ip, user, password, cmd, timeout=10, log=log)
        if rc != 0 or not out or "not recognized" in out.lower() or "invalid" in out.lower() \
           or "error:" in out.lower() and len(out) < 100:
            continue
        # Команда сработала
        result["worked_commands"].append(cmd)
        result["raw"][cmd] = out
        # Парсим параметры, если ещё не найдены
        for key, pat in RADIO_PATTERNS.items():
            if result[key] is None:
                m = pat.search(out)
                if m:
                    val = m.group(1)
                    unit = m.group(2) if m.lastindex and m.lastindex >= 2 else ""
                    result[key] = f"{val}{unit}" if unit else val
                    if log:
                        log(f"[RTN] {ip}: {key} = {result[key]} (из '{cmd}')")
        if all(result[k] is not None for k in ("rsl", "modulation", "frequency", "tx_power")):
            break  # всё найдено
    if log:
        found = {k: v for k, v in result.items() if v and k in ("rsl", "modulation", "frequency", "tx_power")}
        log(f"[RTN] {ip}: найдено параметров: {len(found)}; рабочие команды: {result['worked_commands']}")
    return result


def ssh_to_rtn(ip, user="admin", log=None):
    """Открывает SSH-сессию к RTN в новом окне cmd (встроенный OpenSSH Windows).
    Пароль вводится интерактивно (SSH сам запросит)."""
    ssh = r"C:\Windows\System32\OpenSSH\ssh.exe"
    if not os.path.exists(ssh):
        if log:
            log(f"[RTN] OpenSSH не найден: {ssh}")
        return False
    if log:
        log(f"[RTN] SSH к {user}@{ip}...")
    # Открываем отдельное окно cmd с SSH. -o StrictHostKeyChecking=no чтобы не зависать на yes/no.
    cmd = f'start "SSH {ip}" cmd /k "{ssh}" -o StrictHostKeyChecking=no -o UserKnownHostsFile=NUL {user}@{ip}'
    try:
        subprocess.Popen(["cmd", "/c", cmd], creationflags=NO_WIN)
    except Exception as e:
        if log:
            log(f"[RTN] не открыть SSH: {e}")
        return False
    return True


def telnet_to_rtn(ip, port=23, log=None):
    """Открывает Telnet-сессию к RTN в новом окне cmd (встроенный telnet Windows).
    Логин/пароль вводятся интерактивно."""
    if log:
        log(f"[RTN] Telnet к {ip}:{port}...")
    cmd = f'start "Telnet {ip}" cmd /k telnet {ip} {port}'
    try:
        subprocess.Popen(["cmd", "/c", cmd], creationflags=NO_WIN)
    except Exception as e:
        if log:
            log(f"[RTN] не открыть Telnet: {e}")
        return False
    return True


def backup_rtn_config(ip, user, password, log=None, backup_dir=None):
    """Сохраняет конфигурацию RTN через SSH (plink) в файл.
    Команда: display current-configuration. Файл: <backup_dir>/<ip>_<datetime>.cfg
    Возвращает путь к файлу или None."""
    if not find_plink():
        if log:
            log("[RTN] plink.exe не найден — backup невозможен")
        return None
    if backup_dir is None:
        backup_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "backups")
        if getattr(sys, "frozen", False):
            backup_dir = os.path.join(os.path.dirname(sys.executable), "backups")
    try:
        os.makedirs(backup_dir, exist_ok=True)
    except Exception:
        pass
    rc, out = ssh_exec_plink(ip, user, password, "display current-configuration",
                              timeout=30, log=log)
    if rc != 0 or not out or len(out) < 50:
        if log:
            log(f"[RTN] {ip}: не получить конфиг (rc={rc})")
        return None
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_ip = ip.replace(".", "_")
    fname = os.path.join(backup_dir, f"{safe_ip}_{ts}.cfg")
    try:
        with open(fname, "w", encoding="utf-8", errors="replace") as fh:
            fh.write(f"# RTN config backup: {ip} ({user})\n")
            fh.write(f"# Date: {datetime.now().isoformat()}\n")
            fh.write("#" + "=" * 70 + "\n\n")
            fh.write(out)
    except Exception as e:
        if log:
            log(f"[RTN] не записать файл: {e}")
        return None
    if log:
        log(f"[RTN] {ip}: конфиг сохранён ({len(out)} байт) → {fname}")
    return fname


def save_rtn_list(ips, path, log=None):
    """Сохраняет список IP в файл (по одному на строку)."""
    try:
        with open(path, "w", encoding="utf-8") as fh:
            for ip in sorted(set(ips)):
                fh.write(ip + "\n")
    except Exception as e:
        if log:
            log(f"[RTN] не сохранить список: {e}")
        return False
    if log:
        log(f"[RTN] список сохранён ({len(set(ips))} IP) → {path}")
    return True


def load_rtn_list(path, log=None):
    """Загружает список IP из файла. Возвращает список строк."""
    out = []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                ip = line.strip()
                if ip and re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
                    out.append(ip)
    except Exception as e:
        if log:
            log(f"[RTN] не загрузить список: {e}")
        return []
    if log:
        log(f"[RTN] список загружен ({len(out)} IP) ← {path}")
    return out


def open_rtn_web(ip, log=None):
    """Открывает веб-интерфейс RTN (https://<ip>) в Edge."""
    edge = find_edge()
    url = f"https://{ip}/"
    if log:
        log(f"[RTN] веб-интерфейс {url} ...")
    if edge:
        try:
            subprocess.Popen([edge, "--ignore-certificate-errors",
                              "--no-first-run", "--no-default-browser-check", url],
                             creationflags=NO_WIN)
        except Exception as e:
            if log:
                log(f"[RTN] не открыть Edge: {e}")
            return False
    else:
        try:
            os.startfile(url)
        except Exception:
            pass
    return True


def ping_rtn(ip, log=None):
    """Пингует RTN, возвращает (alive, ms). Для быстрой проверки в таблице."""
    rc, out = run_cmd(["ping", "-n", "1", "-w", "800", ip])
    alive = (rc == 0 and re.search(r"ttl=\d", out, re.I) is not None)
    m = re.search(r"=\d+ms", out)
    ms = m.group(0)[1:] if m else "-"
    if log:
        log(f"[RTN] {ip}: {'жив' if alive else 'недоступен'} ({ms})")
    return alive, ms


def _weblct_login_session(log=None):
    """Логинится в WebLCT (admin/пароль из config.txt) и возвращает
    http.cookiejar.CookieJar с JSESSIONID для последующих запросов.
    None, если WebLCT не запущен или логин не удался."""
    import urllib.request, urllib.parse, ssl, http.cookiejar
    if not weblct_running():
        return None
    root = get_weblct_root()
    if not root:
        return None
    # Читаем пароль из config.txt
    user, passw = "admin", ""
    cfg = os.path.join(root, "helper", "config.txt")
    if os.path.exists(cfg):
        try:
            with open(cfg, "r", encoding="utf-8") as fh:
                for line in fh:
                    m = re.match(r'^\s*set\s+"WEBLCT_USER=(.+)"\s*$', line)
                    if m: user = m.group(1).strip()
                    m = re.match(r'^\s*set\s+"WEBLCT_PASSWORD=(.+)"\s*$', line)
                    if m: passw = m.group(1).strip()
        except Exception:
            pass
    if not passw:
        return None
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj),
                                          urllib.request.HTTPSHandler(context=ctx))
    try:
        # 1. GET login page (получить cookie)
        opener.open(f"https://localhost:{WEBLCT_PORT}/weblct/page/login.html", timeout=5).read()
        # 2. POST login
        data = urllib.parse.urlencode({"txtname": user, "txtpassword": passw}).encode()
        req = urllib.request.Request(f"https://localhost:{WEBLCT_PORT}/weblct/TSLoginCheck",
                                      data=data,
                                      headers={"Referer": f"https://localhost:{WEBLCT_PORT}/weblct/page/login.html"})
        resp = opener.open(req, timeout=5)
        # Успех = редирект на nelistmain.html (а не обратно на login.html?msg=...)
        if "login.html" in (resp.url or "") and "msg=" in (resp.url or ""):
            if log:
                log("[RTN] логин в WebLCT не удался — неверный пароль в config.txt?")
            return None
        return cj
    except Exception as e:
        if log:
            log(f"[RTN] ошибка логина в WebLCT: {e}")
        return None


def _weblct_get(path, cj, log=None, timeout=5):
    """GET-запрос к WebLCT с готовой сессией (cookiejar). Возвращает тело или None."""
    import urllib.request, ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj),
                                          urllib.request.HTTPSHandler(context=ctx))
    try:
        url = f"https://localhost:{WEBLCT_PORT}{path}"
        with opener.open(url, timeout=timeout) as r:
            return r.read().decode("utf-8", errors="replace")
    except Exception as e:
        if log:
            log(f"[RTN] запрос {path} не удался: {e}")
        return None


def query_weblct_ne_list(root, log=None):
    """Опрашивает WebLCT через neListServlet — список заведённых NE.
    Логинится (JSESSIONID), затем запрашивает список.
    Возвращает [{ip, name, neid, status}, ...]."""
    import xml.etree.ElementTree as ET
    if not weblct_running():
        if log:
            log("[RTN] WebLCT не запущен — опрос NE невозможен")
        return []
    cj = _weblct_login_session(log=log)
    if not cj:
        return []
    body = _weblct_get("/weblct/neListServlet", cj, log=log)
    if not body:
        return []
    out = []
    # Парсим XML-ответ
    try:
        root_xml = ET.fromstring(body)
        for elem in root_xml.iter():
            tag = elem.tag.lower()
            if "devinfo" in tag or tag.endswith("row") or tag.endswith("ne"):
                item = {c.tag.lower(): (c.text or "").strip() for c in elem}
                ip = item.get("devip") or item.get("ip") or item.get("neip") or ""
                if ip:
                    out.append({
                        "ip": ip,
                        "name": item.get("name") or item.get("alias") or item.get("nename") or "",
                        "neid": item.get("neid") or item.get("id") or "",
                        "status": item.get("status") or item.get("comstatus") or item.get("logstatus") or "",
                    })
    except ET.ParseError:
        # Возможно JSON
        import json as _json
        try:
            data = _json.loads(body)
            rows = data if isinstance(data, list) else data.get("rows") or data.get("data") or []
            for item in rows:
                ip = str(item.get("devip") or item.get("ip") or "")
                if ip:
                    out.append({
                        "ip": ip,
                        "name": str(item.get("name") or ""),
                        "neid": str(item.get("neid") or item.get("id") or ""),
                        "status": str(item.get("status") or ""),
                    })
        except Exception:
            pass
    if log:
        log(f"[RTN] WebLCT знает {len(out)} устройств")
    return out


# ---------------------------------------------------------------- iphlpapi
from ctypes import wintypes

AF_INET = 2


class SOCKADDR(ctypes.Structure):
    _fields_ = [("sa_family", wintypes.USHORT), ("sa_data", ctypes.c_ubyte * 14)]


class SOCKET_ADDRESS(ctypes.Structure):
    _fields_ = [("lpSockaddr", ctypes.POINTER(SOCKADDR)), ("iSockaddrLength", ctypes.c_int)]


class IP_ADAPTER_UNICAST_ADDRESS(ctypes.Structure):
    pass


IP_ADAPTER_UNICAST_ADDRESS._fields_ = [
    ("Length", wintypes.ULONG), ("Flags", wintypes.DWORD),
    ("Next", ctypes.POINTER(IP_ADAPTER_UNICAST_ADDRESS)),
    ("Address", SOCKET_ADDRESS),
    ("PrefixOrigin", ctypes.c_int), ("SuffixOrigin", ctypes.c_int), ("DadState", ctypes.c_int),
    ("ValidLifetime", wintypes.ULONG), ("PreferredLifetime", wintypes.ULONG),
    ("LeaseLifetime", wintypes.ULONG), ("OnLinkPrefixLength", ctypes.c_ubyte),
]


class IP_ADAPTER_ADDRESSES(ctypes.Structure):
    pass


IP_ADAPTER_ADDRESSES._fields_ = [
    ("Length", wintypes.ULONG), ("IfIndex", wintypes.DWORD),
    ("Next", ctypes.POINTER(IP_ADAPTER_ADDRESSES)),
    ("AdapterName", ctypes.c_char_p),
    ("FirstUnicastAddress", ctypes.POINTER(IP_ADAPTER_UNICAST_ADDRESS)),
    ("FirstAnycastAddress", ctypes.c_void_p),
    ("FirstMulticastAddress", ctypes.c_void_p),
    ("FirstDnsServerAddress", ctypes.c_void_p),
    ("DnsSuffix", ctypes.c_wchar_p),
    ("Description", ctypes.c_wchar_p),
    ("FriendlyName", ctypes.c_wchar_p),
    ("PhysicalAddress", ctypes.c_ubyte * 8),
    ("PhysicalAddressLength", wintypes.DWORD),
    ("Flags", wintypes.DWORD), ("Mtu", wintypes.DWORD),
    ("IfType", wintypes.DWORD), ("OperStatus", ctypes.c_int),
]

IFTYPE = {6: "Ethernet", 71: "Wi-Fi", 24: "loopback", 23: "PPP", 131: "tunnel", 237: "IP-over-IB"}
OPER = {1: "up", 2: "down", 3: "testing", 4: "unknown", 5: "dormant", 6: "not present", 7: "lower layer down"}


def _ifaces_api():
    """Перечисление адаптеров через iphlpapi.GetAdaptersAddresses — есть в любой Windows."""
    size = wintypes.ULONG(15000)
    for _ in range(3):
        buf = ctypes.create_string_buffer(size.value)
        r = ctypes.windll.iphlpapi.GetAdaptersAddresses(
            AF_INET, 0x10, None, ctypes.byref(buf), ctypes.byref(size))
        if r == 111:      # ERROR_BUFFER_OVERFLOW
            continue
        if r != 0:
            return []
        break
    else:
        return []
    out = []
    p = ctypes.cast(buf, ctypes.POINTER(IP_ADAPTER_ADDRESSES))
    while p:
        a = p.contents
        mac = ":".join(f"{a.PhysicalAddress[i]:02x}" for i in range(min(a.PhysicalAddressLength, 8)))
        ips, prefixes = [], []
        u = a.FirstUnicastAddress
        while u:
            sa = u.contents.Address.lpSockaddr
            if sa and sa.contents.sa_family == AF_INET:
                ips.append(".".join(str(b) for b in sa.contents.sa_data[2:6]))
                prefixes.append(u.contents.OnLinkPrefixLength)
            u = u.contents.Next
        out.append({"name": a.FriendlyName or "", "desc": a.Description or "",
                    "mac": mac, "ips": ips, "prefixes": prefixes,
                    "index": a.IfIndex, "iftype": a.IfType, "oper": a.OperStatus})
        p = a.Next
    return out


def send_arp(dst, src="0.0.0.0"):
    """ARP-запрос средствами Windows (iphlpapi.SendARP) — драйвер не нужен."""
    try:
        d = struct.unpack("<L", socket.inet_aton(dst))[0]
        s = struct.unpack("<L", socket.inet_aton(src))[0]
        buf = (ctypes.c_ubyte * 6)()
        ln = ctypes.c_ulong(6)
        if ctypes.windll.iphlpapi.SendARP(d, s, ctypes.byref(buf), ctypes.byref(ln)) == 0 and ln.value == 6:
            mac = ":".join(f"{b:02x}" for b in buf)
            return None if mac == "00:00:00:00:00:00" else mac
    except Exception:
        pass
    return None


def arp_table():
    out = {}
    rc, txt = run_cmd(["arp", "-a"])
    for line in txt.splitlines():
        m = re.match(r"\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})\s+(\S+)", line)
        if m and m.group(3).lower().startswith(("dyn", "дин", "stat", "стат")):
            mac = m.group(2).replace("-", ":").lower()
            if mac not in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
                out[m.group(1)] = mac
    return out


def common_prefix_len(ips):
    if not ips:
        return None
    vals = [int(ipaddress.IPv4Address(i)) for i in ips]
    n = 0
    for b in range(31, -1, -1):
        bit = (vals[0] >> b) & 1
        if all(((v >> b) & 1) == bit for v in vals):
            n += 1
        else:
            break
    return n


def looks_local(ip):
    return not ip.startswith(("169.254.", "224.", "239.", "255.", "0."))


# ---------------------------------------------------------------- probes
class BaseProbe:
    def __init__(self, iface, log, sniff_time=25, mask=26):
        self.iface = iface            # dict из list_ifaces
        self.name = iface["name"]
        self.log = log
        self.sniff_time = sniff_time
        self.mask = mask
        self.stop = threading.Event()
        self.seen = {}
        self.arp_targets = {}
        self.who_asks = {}
        self.bcast_dst = {}
        self.nexthop = {}
        self.names = {}
        self.roles = {}               # ip -> строка-подсказка (ssdp/igd/...)
        self.temp_ip = None
        self.my_mac = (iface.get("mac") or "").lower()

    def note_name(self, ip, payload, sport, dport):
        try:
            if dport == 5353 or sport == 5353:
                m = re.search(rb"([A-Za-z0-9\-_]{2,30})\x05local", payload)
                if m:
                    self.names.setdefault(ip, m.group(1).decode("ascii", "ignore"))
            elif dport == 137:
                m = re.search(rb"\x20([A-P]{32})\x00", payload)
                if m:
                    e = m.group(1).decode()
                    nm = "".join(chr(((ord(e[i]) - 65) << 4) | (ord(e[i + 1]) - 65)) for i in range(0, 32, 2)).strip()
                    if nm:
                        self.names.setdefault(ip, nm)
            elif dport in (1900, 3702) or sport == 1900:
                low = payload.lower()
                if b"internetgatewaydevice" in low:
                    self.roles[ip] = "UPnP InternetGatewayDevice (маршрутизатор)"
                elif b"ssdp" in low or b"upnp" in low:
                    self.roles.setdefault(ip, "UPnP-устройство")
                m = re.search(rb"SERVER:\s*([^\r\n]{3,60})", payload, re.I)
                if m:
                    self.names.setdefault(ip, m.group(1).decode("latin1").strip())
            elif dport == 67 or sport == 67:
                self.roles.setdefault(ip, "DHCP-сервер (часто = шлюз)")
        except Exception:
            pass

    def guess_gateway(self, net, hosts):
        cand = []
        mac2ip = {m.lower(): i for i, m in hosts.items() if m}
        for ip, why in self.roles.items():
            if ip in hosts and "ПОДТВЕРЖДЁН" in why:
                cand.append((ip, why))
        for m, _ in sorted(self.nexthop.items(), key=lambda kv: -kv[1]):
            if m.lower() in mac2ip:
                cand.append((mac2ip[m.lower()], f"L2-next-hop транзитного трафика (MAC {m})"))
                break
        for ip, why in self.roles.items():
            if ip in hosts and any(k in why for k in ("аршрутизатор", "DHCP")):
                cand.append((ip, why))
        for ip, n in sorted(self.arp_targets.items(), key=lambda kv: -kv[1]):
            if ip in hosts and ipaddress.IPv4Address(ip) in net:
                cand.append((ip, f"самый частый ARP-таргет (x{n})"))
                break
        for ip in (str(net.network_address + 1), str(net.broadcast_address - 1)):
            if ip in hosts:
                cand.append((ip, "типовой адрес шлюза в подсети"))
        out, seen = [], set()
        for ip, why in cand:
            if ip not in seen:
                seen.add(ip)
                out.append((ip, why))
        return out

    def cleanup(self):
        if self.temp_ip:
            rc, out = ip_del(self.iface, self.temp_ip)
            self.log(f"[*] временный адрес {self.temp_ip} снят с '{self.name}' ({'ok' if not rc else out})")
            self.temp_ip = None


class ProbeNpcap(BaseProbe):
    """Полный режим: L2-захват и собственные ARP-пакеты. Конфиг адаптера не трогается."""

    def _on_pkt(self, p):
        try:
            eth_src = p[Ether].src if Ether in p else None
            eth_dst = p[Ether].dst if Ether in p else None
            if ARP in p:
                a = p[ARP]
                if a.psrc and a.psrc != "0.0.0.0":
                    self.seen[a.psrc] = a.hwsrc
                if a.op == 1 and a.pdst not in ("0.0.0.0", "255.255.255.255"):
                    self.arp_targets[a.pdst] = self.arp_targets.get(a.pdst, 0) + 1
                    if a.psrc and a.psrc != "0.0.0.0":
                        self.who_asks.setdefault(a.pdst, set()).add(a.psrc)
                return
            if IP in p:
                src, dst = p[IP].src, p[IP].dst
                if looks_local(src) and eth_src:
                    self.seen.setdefault(src, eth_src)
                last = int(dst.split(".")[-1])
                if dst.endswith(".255") or last in (63, 127, 191, 31, 15, 7, 3):
                    self.bcast_dst[dst] = self.bcast_dst.get(dst, 0) + 1
                if eth_dst and eth_dst != BCAST_MAC and not eth_dst.startswith(("01:00:5e", "33:33", "01:80:c2")):
                    if eth_dst != self.my_mac:
                        self.nexthop[eth_dst] = self.nexthop.get(eth_dst, 0) + 1
                if UDP in p:
                    self.note_name(src, bytes(p[UDP].payload), p[UDP].sport, p[UDP].dport)
        except Exception:
            pass

    def passive(self):
        try:
            self.my_mac = get_if_hwaddr(self.name)
        except Exception:
            self.my_mac = self.iface.get("mac")
        self.log(f"[1] Npcap: пассивный захват {self.sniff_time} c (ARP / DHCP / mDNS / NBNS / IP)...")
        sniff(iface=self.name, prn=self._on_pkt, store=False,
              timeout=self.sniff_time, stop_filter=lambda _: self.stop.is_set())

    def _arp(self, pdst, psrc, timeout=2, retry=0):
        ans, _ = srp(Ether(dst=BCAST_MAC) / ARP(op=1, pdst=pdst, psrc=psrc),
                     iface=self.name, timeout=timeout, retry=retry, verbose=0)
        return ans

    def sweep(self, net):
        hosts = [str(h) for h in net.hosts()]
        psrc = hosts[-1]
        for ip in reversed(hosts):
            if ip in self.seen or ip in self.arp_targets:
                continue
            if not self._arp(ip, "0.0.0.0", timeout=1.2):
                psrc = ip
                break
        self.log(f"[3] ARP-скан {net} (source-IP {psrc}, конфиг адаптера не меняется)...")
        found = {}
        for i in range(0, len(hosts), 32):
            if self.stop.is_set():
                break
            for _, r in self._arp(hosts[i:i + 32], psrc, timeout=2, retry=1):
                found[r[ARP].psrc] = r[ARP].hwsrc
        try:
            ans, _ = srp(Ether(dst=BCAST_MAC) / IP(src=psrc, dst=str(net.broadcast_address)) / ICMP(),
                         iface=self.name, timeout=2, verbose=0)
            for _, r in ans:
                found.setdefault(r[IP].src, r[Ether].src)
        except Exception:
            pass
        self.seen.update(found)
        return found


class ProbeND(BaseProbe):
    """Портативный режим: только штатные API Windows, драйверы не нужны."""

    def __init__(self, iface, log, sniff_time=25, mask=26, allow_temp_ip=True, gw_probe=False):
        super().__init__(iface, log, sniff_time, mask)
        self.allow_temp_ip = allow_temp_ip
        self.gw_probe = gw_probe
        self.local_ips = [i for i in iface.get("ips", []) if ":" not in i]
        self.my_mac = (iface.get("mac") or "").lower()

    # ---- пассивная фаза
    def _raw_sniff(self, local_ip, until):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            s.bind((local_ip, 0))
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            s.settimeout(1.0)
        except Exception as e:
            self.log(f"    promisc на {local_ip} недоступен: {e}")
            return
        while time.time() < until and not self.stop.is_set():
            try:
                b = s.recv(65535)
            except socket.timeout:
                continue
            except Exception:
                break
            if len(b) < 20:
                continue
            ihl = (b[0] & 0xF) * 4
            proto = b[9]
            src = socket.inet_ntoa(b[12:16])
            dst = socket.inet_ntoa(b[16:20])
            if looks_local(src):
                self.seen.setdefault(src, "")
            last = int(dst.split(".")[-1])
            if dst.endswith(".255") or last in (63, 127, 191, 31, 15, 7, 3):
                self.bcast_dst[dst] = self.bcast_dst.get(dst, 0) + 1
            if proto == 17 and len(b) >= ihl + 8:
                sp, dp = struct.unpack("!HH", b[ihl:ihl + 4])
                self.note_name(src, b[ihl + 8:], sp, dp)
        try:
            s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            s.close()
        except Exception:
            pass

    def _udp_listen(self, port, until):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s.bind(("", port))
            if port in (5353, 5355, 1900, 3702):
                grp = {5353: "224.0.0.251", 5355: "224.0.0.252",
                       1900: "239.255.255.250", 3702: "239.255.255.250"}[port]
                for lip in self.local_ips or ["0.0.0.0"]:
                    try:
                        s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                                     socket.inet_aton(grp) + socket.inet_aton(lip))
                    except Exception:
                        pass
            s.settimeout(1.0)
        except Exception:
            return
        while time.time() < until and not self.stop.is_set():
            try:
                data, addr = s.recvfrom(65535)
            except socket.timeout:
                continue
            except Exception:
                break
            if looks_local(addr[0]):
                self.seen.setdefault(addr[0], "")
                self.note_name(addr[0], data, addr[1], port)
        try:
            s.close()
        except Exception:
            pass

    def _arp_poll(self, until):
        while time.time() < until and not self.stop.is_set():
            for ip, mac in arp_table().items():
                if looks_local(ip) and not self.seen.get(ip):
                    self.seen[ip] = mac
            time.sleep(2)

    def passive(self):
        self.log(f"[1] Портативный режим (без драйверов): слушаю {self.sniff_time} c...")
        if not self.local_ips:
            self.log("    у адаптера нет IPv4 — promisc-захват невозможен, только UDP-широковещание")
        until = time.time() + self.sniff_time
        th = [threading.Thread(target=self._arp_poll, args=(until,), daemon=True)]
        for lip in self.local_ips:
            th.append(threading.Thread(target=self._raw_sniff, args=(lip, until), daemon=True))
        for p in LISTEN_PORTS:
            th.append(threading.Thread(target=self._udp_listen, args=(p, until), daemon=True))
        for t in th:
            t.start()
        self._ssdp_poke()
        for t in th:
            t.join(timeout=self.sniff_time + 5)

    def _ssdp_poke(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            s.sendto(SSDP_MSEARCH, ("239.255.255.250", 1900))
            s.close()
        except Exception:
            pass

    # ---- активная фаза
    def _ensure_onlink(self, net):
        for ip in self.local_ips:
            if ipaddress.IPv4Address(ip) in net:
                return ip
        if not self.allow_temp_ip:
            self.log("    ! нет адреса в этой подсети, а временный IP запрещён галкой — ARP-скан пропущен")
            return None
        if not is_admin():
            self.log("    ! нужны права администратора для назначения временного адреса")
            return None
        busy = set(self.seen) | set(self.arp_targets)
        for h in list(net.hosts())[::-1]:
            cand = str(h)
            if cand in busy:
                continue
            rc, out = ip_set_static(self.iface, cand, str(net.netmask), None, add=True)
            if rc:
                self.log(f"    netsh add {cand}: {out}")
                continue
            time.sleep(1.5)
            mac = send_arp(cand)
            txt = ip_show(self.iface)
            if (mac and mac != self.my_mac) or re.search(r"Duplicate|Дубликат", txt, re.I):
                self.log(f"    {cand} занят — пробую следующий")
                ip_del(self.iface, cand)
                continue
            self.temp_ip = cand
            self.log(f"[2b] на '{self.name}' временно добавлен {cand}/{net.prefixlen} (будет снят после скана)")
            return cand
        return None

    @staticmethod
    def _ping(ip):
        rc, out = run_cmd(["ping", "-n", "1", "-w", "600", ip])
        return bool(rc == 0 and re.search(r"ttl=", out, re.I))

    @staticmethod
    def _tcp(ip, ports=(80, 443, 22, 23, 8080, 445, 502)):
        for p in ports:
            s = socket.socket()
            s.settimeout(0.35)
            try:
                if s.connect_ex((ip, p)) == 0:
                    return p
            except Exception:
                pass
            finally:
                s.close()
        return None

    def sweep(self, net):
        hosts = [str(h) for h in net.hosts()]
        found = {}
        src = self._ensure_onlink(net)
        if src:
            self.log(f"[3] ARP-скан {net} через iphlpapi.SendARP (без драйверов)...")
            tgt = [h for h in hosts if h != src]
            with ThreadPoolExecutor(max_workers=32) as ex:
                for ip, mac in zip(tgt, ex.map(send_arp, tgt)):
                    if self.stop.is_set():
                        break
                    if mac:
                        found[ip] = mac
            run_cmd(["ping", "-n", "1", "-w", "500", str(net.broadcast_address)])
            for ip, mac in arp_table().items():
                if ipaddress.IPv4Address(ip) in net:
                    found.setdefault(ip, mac)
        if not found:
            self.log(f"[3b] ARP недоступен (нет адреса в {net}) — ping-скан через маршрутизацию...")
            with ThreadPoolExecutor(max_workers=48) as ex:
                for ip, ok in zip(hosts, ex.map(self._ping, hosts)):
                    if self.stop.is_set():
                        break
                    if ok:
                        found[ip] = ""
            for ip, mac in arp_table().items():
                if ipaddress.IPv4Address(ip) in net:
                    found[ip] = mac
        if not found:
            self.log("[3c] ICMP молчит — добиваю TCP-пробой (80/443/22/23/8080/445/502)...")
            with ThreadPoolExecutor(max_workers=48) as ex:
                for ip, port in zip(hosts, ex.map(self._tcp, hosts)):
                    if self.stop.is_set():
                        break
                    if port:
                        found[ip] = ""
                        self.roles.setdefault(ip, f"открыт TCP/{port}")
        self.seen.update({k: v for k, v in found.items() if v or k not in self.seen})
        if self.gw_probe:
            self._probe_routers(net, found)
        return found

    def _probe_routers(self, net, hosts, test_ip="8.8.8.8"):
        self.log(f"[4] Проверка кандидатов в шлюз (временный маршрут до {test_ip})...")
        order = [str(net.network_address + 1), str(net.broadcast_address - 1)] + list(hosts)
        for ip in dict.fromkeys(order):
            if ip not in hosts or self.stop.is_set():
                continue
            run_cmd(["route", "delete", test_ip])
            rc, _ = run_cmd(["route", "add", test_ip, "mask", "255.255.255.255", ip, "metric", "1"])
            if rc:
                continue
            rc2, out = run_cmd(["ping", "-n", "1", "-w", "800", test_ip])
            run_cmd(["route", "delete", test_ip])
            if rc2 == 0 and re.search(r"ttl=", out, re.I):
                self.roles[ip] = "ПОДТВЕРЖДЁН: маршрутизирует трафик наружу"
                self.log(f"    {ip} -> маршрутизирует наружу")
                return ip
        self.log("    ни один кандидат не пропустил трафик наружу")
        return None


# ---------------------------------------------------------------- ifaces
def list_ifaces(show_all=False):
    out = []
    for d in _ifaces_api():
        if not show_all and (d["iftype"] not in (6, 71) or not d["mac"]):
            continue
        addr = ", ".join(f"{ip}/{p}" for ip, p in zip(d["ips"], d["prefixes"])) or "без IPv4"
        d["label"] = (f"[{IFTYPE.get(d['iftype'], d['iftype'])}/{OPER.get(d['oper'], '?')}] "
                      f"{d['name']} — {d['desc']}  [{addr}]  {d['mac']}")
        out.append(d)
    out.sort(key=lambda d: (d["oper"] != 1, d["iftype"] != 6, d["name"]))
    return out


# ---------------------------------------------------------------- GUI
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("NetProbe — IP устройства, шлюз, соседи + настройка IPv4")
        self.geometry("1000x700")
        self.q = queue.Queue()
        self.probe = None
        self.free_pool = []
        self.free_mask = ""

        top = ttk.Frame(self, padding=8)
        top.pack(fill="x")
        ttk.Label(top, text="Интерфейс:").grid(row=0, column=0, sticky="w")
        self.if_box = ttk.Combobox(top, width=72, state="readonly")
        self.if_box.grid(row=0, column=1, columnspan=4, sticky="we", padx=4)
        self.show_all = tk.BooleanVar(value=False)
        ttk.Checkbutton(top, text="все", variable=self.show_all,
                        command=self.reload_ifaces).grid(row=0, column=5, sticky="w")
        self.ifaces = []
        self.reload_ifaces()

        ttk.Label(top, text="Маска /").grid(row=1, column=0, sticky="w", pady=(6, 0))
        self.mask = tk.IntVar(value=26)
        ttk.Spinbox(top, from_=8, to=30, width=5, textvariable=self.mask).grid(row=1, column=1, sticky="w", pady=(6, 0))
        ttk.Label(top, text="Слушать, с:").grid(row=1, column=2, sticky="e", pady=(6, 0))
        self.stime = tk.IntVar(value=25)
        ttk.Spinbox(top, from_=5, to=300, width=6, textvariable=self.stime).grid(row=1, column=3, sticky="w", pady=(6, 0))
        ttk.Label(top, text="Подсказка (IP/подсеть):").grid(row=1, column=4, sticky="e", pady=(6, 0))
        self.hint = ttk.Entry(top, width=18)
        self.hint.grid(row=1, column=5, sticky="w", pady=(6, 0))

        eng = ttk.Frame(self, padding=(8, 4))
        eng.pack(fill="x")
        ttk.Label(eng, text="Движок:").pack(side="left")
        self.engine = tk.StringVar(value="auto")
        for v, t in (("auto", "авто"), ("npcap", "Npcap (полный L2)"), ("nd", "портативный (без драйверов)")):
            ttk.Radiobutton(eng, text=t, variable=self.engine, value=v).pack(side="left", padx=4)
        self.allow_temp = tk.BooleanVar(value=True)
        ttk.Checkbutton(eng, text="разрешить временный IP на адаптере (снимается после скана)",
                        variable=self.allow_temp).pack(side="left", padx=10)
        self.gw_probe = tk.BooleanVar(value=False)
        ttk.Checkbutton(eng, text="проверять шлюз (route add/delete)",
                        variable=self.gw_probe).pack(side="left")

        btns = ttk.Frame(self, padding=(8, 0))
        btns.pack(fill="x")
        self.btn = ttk.Button(btns, text="СКАНИРОВАТЬ", command=self.start)
        self.btn.pack(side="left")
        self.btn_stop = ttk.Button(btns, text="Стоп", command=self.stop, state="disabled")
        self.btn_stop.pack(side="left", padx=6)
        ttk.Button(btns, text="Сохранить отчёт", command=self.save).pack(side="left")
        if not is_admin():
            ttk.Button(btns, text="Перезапустить от администратора",
                       command=self.elevate).pack(side="left", padx=6)
        self.status = ttk.Label(btns, text="")
        self.status.pack(side="left", padx=12)

        # ---- Панель WebLCT ----
        wl = ttk.LabelFrame(self, text="WebLCT", padding=6)
        wl.pack(fill="x", padx=8, pady=(8, 0))
        self.wl_root = get_weblct_root(self.log)
        self.wl_status_var = tk.StringVar(value="? проверяю…")
        self.wl_lbl = ttk.Label(wl, textvariable=self.wl_status_var, width=26,
                                foreground="#888")
        self.wl_lbl.grid(row=0, column=0, sticky="w")
        ttk.Button(wl, text="Запустить процесс и открыть WebLCT",
                   command=self.wl_start_full).grid(row=0, column=1, padx=6)
        ttk.Button(wl, text="Закрыть процессы",
                   command=self.wl_stop).grid(row=0, column=2, padx=6)
        ttk.Button(wl, text="Открыть WebLCT",
                   command=self.wl_open_browser).grid(row=0, column=3, padx=6)
        ttk.Label(wl, text="(старт + Edge с автологином; лишнее окно закроется автоматически)",
                  foreground="gray").grid(row=1, column=1, columnspan=4, sticky="w")
        self.wl_running_thread = False
        self.after(500, self.wl_poll)
        # Найденные RTN: список IP (из сканера и WebLCT)
        self.rtn_ips = []

        # ---- Панель RTN ----
        rtn = ttk.LabelFrame(self, text="RTN (найденные IP из сканера + из WebLCT)", padding=6)
        rtn.pack(fill="x", padx=8, pady=(8, 0))
        # Список найденных IP (Treeview): IP | источник | статус пинга
        rtn_top = ttk.Frame(rtn)
        rtn_top.pack(fill="x")
        ttk.Label(rtn_top, text="Устройство:").pack(side="left")
        self.rtn_ip_var = tk.StringVar()
        self.rtn_box = ttk.Combobox(rtn_top, textvariable=self.rtn_ip_var, width=24, state="readonly")
        self.rtn_box.pack(side="left", padx=6)
        self.rtn_box.bind("<<ComboboxSelected>>", lambda e: None)
        ttk.Button(rtn_top, text="Обновить список", command=self.rtn_refresh).pack(side="left", padx=4)
        ttk.Button(rtn_top, text="Пинг", command=self.rtn_ping).pack(side="left", padx=4)
        # Действия с выбранным IP
        rtn_btns = ttk.Frame(rtn)
        rtn_btns.pack(fill="x", pady=(4, 0))
        ttk.Label(rtn_btns, text="Логин:").pack(side="left")
        self.rtn_user_var = tk.StringVar(value="admin")
        ttk.Entry(rtn_btns, textvariable=self.rtn_user_var, width=12).pack(side="left", padx=4)
        ttk.Button(rtn_btns, text="SSH", command=self.rtn_ssh).pack(side="left", padx=4)
        ttk.Button(rtn_btns, text="Веб RTN", command=self.rtn_web).pack(side="left", padx=4)
        ttk.Button(rtn_btns, text="Опросить все (WebLCT)", command=self.rtn_query_all).pack(side="left", padx=4)
        ttk.Button(rtn_btns, text="📊 Таблица статусов", command=self.rtn_show_status_table).pack(side="left", padx=4)
        ttk.Button(rtn_btns, text="📡 Ping-монитор", command=self.rtn_ping_monitor).pack(side="left", padx=4)
        ttk.Button(rtn_btns, text="📻 Радио (SSH)", command=self.rtn_radio_probe).pack(side="left", padx=4)
        ttk.Label(rtn, text="(после сканера IP появятся здесь автоматически)",
                  foreground="gray").pack(anchor="w", pady=(2, 0))

        cfg = ttk.LabelFrame(self, text="IPv4 выбранного адаптера", padding=6)
        cfg.pack(fill="x", padx=8, pady=(8, 0))
        self.ipmode = tk.StringVar(value="fixed")
        ttk.Radiobutton(cfg, text="Автоматически (DHCP)", variable=self.ipmode,
                        value="dhcp").grid(row=0, column=0, sticky="w")
        ttk.Radiobutton(cfg, text="Статический:", variable=self.ipmode,
                        value="fixed").grid(row=1, column=0, sticky="w")
        self.e_ip = ttk.Entry(cfg, width=17)
        self.e_ip.insert(0, "129.9.255.254")
        self.e_ip.grid(row=1, column=1, padx=4)
        ttk.Label(cfg, text="маска").grid(row=1, column=2)
        self.e_mask = ttk.Entry(cfg, width=17)
        self.e_mask.insert(0, "255.255.0.0")
        self.e_mask.grid(row=1, column=3, padx=4)
        ttk.Label(cfg, text="(шлюз не задаётся)").grid(row=1, column=4, sticky="w")
        ttk.Radiobutton(cfg, text="Свободный адрес из найденного диапазона", variable=self.ipmode,
                        value="free").grid(row=2, column=0, columnspan=2, sticky="w")
        self.free_lbl = ttk.Label(cfg, text="— сначала выполните скан —", foreground="gray")
        self.free_lbl.grid(row=2, column=2, columnspan=3, sticky="w")
        self.add_alias = tk.BooleanVar(value=False)
        ttk.Checkbutton(cfg, text="добавить вторым адресом (не сбрасывать текущий)",
                        variable=self.add_alias).grid(row=3, column=0, columnspan=3, sticky="w", pady=(4, 0))
        ttk.Button(cfg, text="Применить", command=self.apply_ip).grid(row=3, column=3, sticky="w", pady=(4, 0))
        ttk.Button(cfg, text="Показать текущий", command=self.show_ip).grid(row=3, column=4, sticky="w", pady=(4, 0))

        self.txt = tk.Text(self, wrap="none", font=("Consolas", 10))
        self.txt.pack(fill="both", expand=True, padx=8, pady=8)
        sb = ttk.Scrollbar(self.txt, command=self.txt.yview)
        sb.pack(side="right", fill="y")
        self.txt["yscrollcommand"] = sb.set

        self._caps()
        self.after(100, self.pump)

    def _caps(self):
        adm = is_admin()
        npc = SCAPY and has_npcap()
        self.log("=== возможности на этой машине ===")
        self.log(f"  права администратора : {'ДА' if adm else 'НЕТ'}")
        self.log(f"  Npcap (полный L2)    : {'ДА' if npc else 'НЕТ'}")
        self.log(f"  адаптеров найдено    : {len(self.ifaces)} (iphlpapi, драйверы не нужны)")
        self.log("  всегда доступно      : ARP-кэш, SendARP-скан, UDP-широковещание, ping/TCP-скан")
        if not adm:
            self.log("  БЕЗ АДМИНА недоступно : promisc-захват, назначение IP, временный IP для скана")
            self.log("  -> пассивный поиск адреса устройства работает; для полного скана нажмите"
                     " 'Перезапустить от администратора'")
        self.log("Подключите ПК к устройству (напрямую или в тот же коммутатор) и нажмите СКАНИРОВАТЬ.")

    def elevate(self):
        if relaunch_admin():
            self.destroy()
        else:
            messagebox.showwarning("NetProbe", "Не удалось повысить права (UAC отклонён или запрещён политикой).")

    # ---- utils
    def cur_iface(self):
        i = self.if_box.current()
        return self.ifaces[i] if 0 <= i < len(self.ifaces) else None

    def reload_ifaces(self):
        prev = self.cur_iface()["name"] if self.ifaces and self.if_box.current() >= 0 else None
        self.ifaces = list_ifaces(self.show_all.get())
        self.if_box["values"] = [d["label"] for d in self.ifaces]
        if self.ifaces:
            self.if_box.current(next((i for i, d in enumerate(self.ifaces) if d["name"] == prev), 0))

    def log(self, s):
        self.q.put(s)

    def pump(self):
        try:
            while True:
                self.txt.insert("end", self.q.get_nowait() + "\n")
                self.txt.see("end")
        except queue.Empty:
            pass
        self.after(100, self.pump)

    def save(self):
        f = filedialog.asksaveasfilename(defaultextension=".txt",
                                         initialfile=f"netprobe_{datetime.now():%Y%m%d_%H%M%S}.txt")
        if f:
            with open(f, "w", encoding="utf-8") as fh:
                fh.write(self.txt.get("1.0", "end"))

    # ---- IP config
    def show_ip(self):
        d = self.cur_iface()
        if d:
            self.log(f"--- netsh show addresses '{d['name']}' ---\n{ip_show(d)}")

    def apply_ip(self):
        d = self.cur_iface()
        if not d:
            return
        if not is_admin():
            if messagebox.askyesno("NetProbe", "Нужны права администратора. Перезапустить с повышением прав?"):
                self.elevate()
            return
        n = d["name"]
        mode = self.ipmode.get()
        if mode == "dhcp":
            if not messagebox.askyesno("Подтверждение", f"Перевести '{n}' на DHCP?"):
                return
            rc, out = ip_set_dhcp(d)
        else:
            if mode == "fixed":
                ip, mask = self.e_ip.get().strip(), self.e_mask.get().strip()
            else:
                if not self.free_pool:
                    messagebox.showwarning("NetProbe", "Свободные адреса неизвестны — выполните скан.")
                    return
                ip, mask = self.free_pool[0], self.free_mask
            try:
                ipaddress.IPv4Address(ip), ipaddress.IPv4Address(mask)
            except Exception:
                messagebox.showerror("NetProbe", "Некорректный IP или маска.")
                return
            act = "ДОБАВИТЬ вторым адресом" if self.add_alias.get() else "ЗАМЕНИТЬ конфигурацию на"
            if not messagebox.askyesno("Подтверждение", f"{act}\n\n{ip} / {mask}\n\nадаптер '{n}'?"):
                return
            rc, out = ip_set_static(d, ip, mask, None, self.add_alias.get())
        self.log(f"--- netsh ({'ok' if not rc else 'rc=' + str(rc)}) ---\n{out or '(без вывода)'}\n{ip_show(d)}")
        self.reload_ifaces()

    # ---- scan
    def start(self):
        d = self.cur_iface()
        if not d:
            messagebox.showerror("NetProbe", "Не найдено интерфейсов.")
            return
        eng = self.engine.get()
        if eng == "auto":
            eng = "npcap" if (SCAPY and has_npcap()) else "nd"
        if eng == "npcap" and not (SCAPY and has_npcap()):
            messagebox.showerror("NetProbe", "Npcap не установлен — выберите портативный режим.")
            return
        self.txt.delete("1.0", "end")
        self.btn["state"] = "disabled"
        self.btn_stop["state"] = "normal"
        self.status["text"] = "работаю..."
        if eng == "npcap":
            self.probe = ProbeNpcap(d, self.log, self.stime.get(), self.mask.get())
        else:
            self.probe = ProbeND(d, self.log, self.stime.get(), self.mask.get(),
                                 self.allow_temp.get(), self.gw_probe.get())
        threading.Thread(target=self.run, args=(self.probe, self.hint.get().strip()), daemon=True).start()

    def stop(self):
        if self.probe:
            self.probe.stop.set()

    def run(self, pr, hint):
        try:
            pr.passive()
            self._report_passive(pr)

            cands = []
            if hint:
                try:
                    cands.append(ipaddress.ip_network(hint if "/" in hint else f"{hint}/{pr.mask}", strict=False))
                except Exception:
                    pr.log(f"    подсказка '{hint}' не распознана")
            src_ips = sorted({i for i in pr.seen if looks_local(i)}, key=ipaddress.IPv4Address)
            all_ips = src_ips + [i for i in pr.arp_targets if looks_local(i)]

            pr.log("[2] Определение подсети:")
            if all_ips:
                cpl = common_prefix_len(sorted(set(all_ips)))
                pr.log(f"    общий префикс услышанных адресов: /{cpl}")
                if cpl < pr.mask:
                    pr.log(f"    => адреса выходят за границу /{pr.mask}: трафик нескольких подсетей "
                           f"либо реальная маска шире (/{cpl})")
            for b, n in sorted(pr.bcast_dst.items(), key=lambda kv: -kv[1])[:5]:
                pr.log(f"    direct-broadcast {b} x{n} -> подсказка о границе подсети")
            for ip in src_ips:
                n = ipaddress.ip_network(f"{ip}/{pr.mask}", strict=False)
                if n not in cands:
                    cands.append(n)
            if not cands:
                pr.log("    подсеть не определена — устройство молчит. Что делать:")
                pr.log("      • увеличить время прослушивания до 120-300 с")
                pr.log("      • перезагрузить устройство при подключённом кабеле (при старте шлёт ARP/DHCP)")
                pr.log("      • вписать предполагаемый адрес в поле 'Подсказка'")
                return

            hosts_all = {}
            for net in cands[:3]:
                if pr.stop.is_set():
                    break
                found = pr.sweep(net)
                pr.log(f"    живых хостов: {len(found)}")
                hosts_all.update(found)
            self._report(pr, cands[0], hosts_all, src_ips)
        except Exception as e:
            pr.log(f"ОШИБКА: {e!r}")
        finally:
            try:
                pr.cleanup()
            except Exception:
                pass
            self.q.put("--- готово ---")
            self.after(0, self._done)

    def _report_passive(self, pr):
        pr.log(f"    услышано источников: {len(pr.seen)}, ARP-запросов к {len(pr.arp_targets)} адресам")
        for ip in sorted(pr.seen, key=ipaddress.IPv4Address):
            pr.log(f"      src {ip:<15} {pr.seen[ip] or '-':<18} {pr.names.get(ip,'')} {pr.roles.get(ip,'')}")
        for ip, n in sorted(pr.arp_targets.items(), key=lambda kv: -kv[1])[:10]:
            pr.log(f"      who-has {ip:<15} x{n} от {', '.join(sorted(pr.who_asks.get(ip, []))) or '?'}")

    def _report(self, pr, net, hosts_all, src_ips):
        pr.log("\n" + "=" * 78 + "\nРЕЗУЛЬТАТ\n" + "=" * 78)
        pr.log(f"Подсеть: {net}   хосты {net.network_address + 1} - {net.broadcast_address - 1}"
               f"   broadcast {net.broadcast_address}")
        gw = pr.guess_gateway(net, hosts_all)
        if gw:
            pr.log("Шлюз (по убыванию вероятности):")
            for ip, why in gw:
                pr.log(f"   {ip:<15} — {why}")
        else:
            pr.log("Шлюз: не определён (нет признаков маршрутизации)")
        talkers = set(pr.seen) | set(hosts_all)
        pr.log(f"Устройства в сети ({len(talkers)}):")
        pr.log(f"   {'IP':<16}{'MAC':<20}{'источник':<12}имя / роль")
        for ip in sorted(talkers, key=ipaddress.IPv4Address):
            mac = hosts_all.get(ip) or pr.seen.get(ip) or ""
            src = "ARP-скан" if ip in hosts_all else "пассивно"
            pr.log(f"   {ip:<16}{mac:<20}{src:<12}{pr.names.get(ip,'')} {pr.roles.get(ip,'')}")
        if src_ips:
            pr.log("\nКандидаты на 'искомое устройство' (говорили ДО скана): " + ", ".join(src_ips))
        occupied = set(pr.seen) | set(hosts_all) | set(pr.arp_targets) | {pr.temp_ip}
        free = [str(h) for h in net.hosts() if str(h) not in occupied][::-1]
        self.free_pool, self.free_mask = free, str(net.netmask)
        if free:
            pr.log(f"Свободные адреса ({len(free)}): {', '.join(free[:8])}" + (" ..." if len(free) > 8 else ""))
            self.after(0, lambda: self.free_lbl.config(
                text=f"{free[0]} / {net.netmask}  (свободных: {len(free)})", foreground="black"))

    # ---- WebLCT control ----
    def wl_poll(self):
        """Периодическая проверка: работает ли WebLCT (порт 13443)."""
        up = weblct_running()
        if up:
            self.wl_status_var.set("● WebLCT работает")
            self.wl_lbl.config(foreground="#1a7f37")
        else:
            self.wl_status_var.set("○ WebLCT остановлен")
            self.wl_lbl.config(foreground="#b00")
        self.after(5000, self.wl_poll)

    def _ensure_root(self):
        """Гарантирует, что self.wl_root задан; если нет — спрашивает у пользователя."""
        if self.wl_root and os.path.exists(os.path.join(self.wl_root, "startweblct.bat")):
            return self.wl_root
        root = get_weblct_root(self.log)
        if root:
            self.wl_root = root
            return root
        return self.wl_ask_path()

    def wl_ask_path(self):
        """Диалог выбора каталога WebLCT; сохраняет выбор в config-файл."""
        from tkinter import filedialog, messagebox
        d = filedialog.askdirectory(title="Укажите каталог WebLCT (где лежит startweblct.bat)")
        if d:
            if os.path.exists(os.path.join(d, "startweblct.bat")):
                self.wl_root = d
                set_weblct_root(d)
                self.log(f"[WebLCT] путь установлен: {d}")
                return d
            else:
                messagebox.showwarning("NetProbe",
                    f"В выбранном каталоге нет startweblct.bat:\n{d}\n\nЭто точно каталог WebLCT?")
        return None

    def wl_start_full(self):
        """Запуск WebLCT с нуля: поднятие Tomcat + Edge с автологином."""
        if self.wl_running_thread:
            messagebox.showinfo("NetProbe", "Операция WebLCT уже выполняется — подождите.")
            return
        root = self._ensure_root()
        if not root:
            return
        self.wl_running_thread = True
        def work():
            try:
                start_weblct(root, language="1", log=self.log)
            finally:
                self.wl_running_thread = False
        threading.Thread(target=work, daemon=True).start()

    def wl_stop(self):
        """Закрыть процессы WebLCT (Tomcat/javaw) и браузеры автологина."""
        if self.wl_running_thread:
            messagebox.showinfo("NetProbe", "Операция WebLCT уже выполняется — подождите.")
            return
        root = self._ensure_root()
        if not root:
            return
        self.wl_running_thread = True
        def work():
            try:
                self.log("[WebLCT] === ЗАКРЫТИЕ ===")
                close_weblct_browsers(log=self.log)
                stop_weblct(root, log=self.log)
            finally:
                self.wl_running_thread = False
        threading.Thread(target=work, daemon=True).start()

    def wl_open_browser(self):
        """Открыть Edge с автологином (если случайно закрыли браузер).
        Tomcat должен быть запущен — иначе входить некуда."""
        root = self._ensure_root()
        if not root:
            return
        if not weblct_running():
            messagebox.showwarning("NetProbe",
                "WebLCT (Tomcat) не запущен. Сначала нажмите «Запустить процесс и открыть WebLCT».")
            return
        open_weblct_browser(root, log=self.log)

    # ---- RTN ----
    def _rtn_add_ip(self, ip, source):
        """Добавить IP в список RTN, если его там ещё нет."""
        if not ip:
            return
        for entry in self.rtn_ips:
            if entry["ip"] == ip:
                return
        self.rtn_ips.append({"ip": ip, "source": source})

    def _rtn_update_combo(self):
        """Обновить выпадающий список IP в панели RTN."""
        items = [f'{e["ip"]}  ({e["source"]})' for e in self.rtn_ips]
        self.rtn_box["values"] = items
        if items and not self.rtn_box.get():
            self.rtn_box.current(0)

    def rtn_refresh(self):
        """Обновить список RTN: берём живые IP из последнего скана + из WebLCT."""
        # 1. Из последнего скана (self.probe.seen / hosts_all)
        self.rtn_ips = []
        if self.probe:
            for ip in sorted(self.probe.seen.keys() | set(getattr(self.probe, "arp_targets", {}).keys())):
                if looks_local(ip):
                    self._rtn_add_ip(ip, "скан")
        # 2. Из WebLCT (заведённые NE)
        root = get_weblct_root()
        if root and weblct_running():
            try:
                nes = query_weblct_ne_list(root, log=self.log)
                for ne in nes:
                    if ne.get("ip"):
                        self._rtn_add_ip(ne["ip"], f'WebLCT: {ne.get("name","")}')
            except Exception as e:
                self.log(f"[RTN] не получить список из WebLCT: {e}")
        self._rtn_update_combo()
        self.log(f"[RTN] в списке {len(self.rtn_ips)} устройств")

    def _rtn_selected_ip(self):
        """Возвращает выбранный IP (без суффикса-источника) или None."""
        val = self.rtn_box.get()
        if not val:
            messagebox.showinfo("NetProbe", "Выберите RTN из списка или сначала выполните скан.")
            return None
        return val.split(" ")[0].strip()

    def rtn_ping(self):
        ip = self._rtn_selected_ip()
        if not ip:
            return
        def work():
            ping_rtn(ip, log=self.log)
        threading.Thread(target=work, daemon=True).start()

    def rtn_ssh(self):
        ip = self._rtn_selected_ip()
        if not ip:
            return
        ssh_to_rtn(ip, user=self.rtn_user_var.get().strip() or "admin", log=self.log)

    def rtn_web(self):
        ip = self._rtn_selected_ip()
        if not ip:
            return
        open_rtn_web(ip, log=self.log)

    def rtn_query_all(self):
        """Массовый опрос: пинг всех IP из списка + статус из WebLCT."""
        if not self.rtn_ips:
            messagebox.showinfo("NetProbe", "Список RTN пуст. Сначала выполните скан или «Обновить список».")
            return
        self.log(f"[RTN] === опрос {len(self.rtn_ips)} устройств ===")
        def work():
            for e in self.rtn_ips:
                ip = e["ip"]
                alive, ms = ping_rtn(ip)
                self.log(f"  {ip:<16} {'ЖИВ' if alive else 'недоступен':<12} {ms}")
        threading.Thread(target=work, daemon=True).start()

    def rtn_show_status_table(self):
        """Открывает отдельное окно с таблицей всех RTN: IP, имя, NE-ID,
        статус (из WebLCT), пинг. Кнопка «Обновить» — пересборка."""
        win = tk.Toplevel(self)
        win.title("Статус RTN")
        win.geometry("780x420")
        top = ttk.Frame(win, padding=6)
        top.pack(fill="x")
        ttk.Label(top, text="Список RTN (из WebLCT + найденные сканером)",
                  font=("", 10, "bold")).pack(side="left")
        tree_frame = ttk.Frame(win)
        tree_frame.pack(fill="both", expand=True, padx=6, pady=4)
        cols = ("ip", "name", "neid", "status", "ping")
        tree = ttk.Treeview(tree_frame, columns=cols, show="headings", height=14)
        for c, w, t in (("ip", 140, "IP"), ("name", 180, "Имя"),
                        ("neid", 80, "NE-ID"), ("status", 140, "Статус WebLCT"),
                        ("ping", 90, "Пинг")):
            tree.heading(c, text=t)
            tree.column(c, width=w, anchor="w")
        sb = ttk.Scrollbar(tree_frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=sb.set)
        tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

        def refresh():
            for i in tree.get_children():
                tree.delete(i)
            rows = []
            # 1. Из WebLCT
            root = get_weblct_root()
            if root and weblct_running():
                try:
                    for ne in query_weblct_ne_list(root, log=self.log):
                        rows.append({"ip": ne["ip"], "name": ne["name"],
                                     "neid": ne["neid"], "status": ne["status"], "src": "WebLCT"})
                except Exception as e:
                    self.log(f"[RTN] опрос WebLCT не удался: {e}")
            # 2. Из сканера (дополнить те, кого нет в WebLCT)
            seen_ips = {r["ip"] for r in rows}
            if self.probe:
                for ip in sorted(self.probe.seen.keys()):
                    if ip not in seen_ips and looks_local(ip):
                        rows.append({"ip": ip, "name": "", "neid": "",
                                     "status": "(не в WebLCT)", "src": "скан"})
            for r in rows:
                tree.insert("", "end", iid=r["ip"], values=(r["ip"], r["name"], r["neid"], r["status"], "…"))
            self.log(f"[RTN] таблица: {len(rows)} устройств")

        def ping_all():
            """Пингует все строки в фоне, обновляет колонку ping."""
            ips = [tree.item(i)["values"][0] for i in tree.get_children()]
            if not ips:
                return
            def work():
                for ip in ips:
                    alive, ms = ping_rtn(str(ip))
                    try:
                        if tree.winfo_exists():
                            cur = list(tree.item(str(ip))["values"])
                            if len(cur) >= 5:
                                cur[4] = f"{'ЖИВ ' if alive else '— '}{ms}"
                                tree.item(str(ip), values=cur)
                    except Exception:
                        pass
            threading.Thread(target=work, daemon=True).start()

        def on_dblclick(_):
            """Двойной клик по строке — открыть SSH к этому RTN."""
            sel = tree.selection()
            if sel:
                ip = str(tree.item(sel[0])["values"][0])
                ssh_to_rtn(ip, user=self.rtn_user_var.get().strip() or "admin", log=self.log)

        tree.bind("<Double-1>", on_dblclick)
        ttk.Button(top, text="Обновить", command=refresh).pack(side="right", padx=4)
        ttk.Button(top, text="Пинг всех", command=ping_all).pack(side="right", padx=4)
        ttk.Label(win, text="Двойной клик по строке — SSH к RTN",
                  foreground="gray").pack(anchor="w", padx=8)
        refresh()
        ping_all()

    def rtn_ping_monitor(self):
        """Непрерывный ping-мониторинг выбранных RTN с алертом при падении.
        Отдельное окно с таблицей: IP | статус | время отклика | счётчик.
        Зелёный — жив, красный — упал (мигает + звук при переходе в красный)."""
        import winsound
        win = tk.Toplevel(self)
        win.title("Ping-мониторинг RTN")
        win.geometry("620x440")
        top = ttk.Frame(win, padding=6)
        top.pack(fill="x")
        ttk.Label(top, text="Интервал, сек:").pack(side="left")
        interval_var = tk.IntVar(value=3)
        ttk.Spinbox(top, from_=1, to=60, width=4, textvariable=interval_var).pack(side="left", padx=4)
        sound_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(top, text="звук при падении", variable=sound_var).pack(side="left", padx=8)
        running_var = tk.BooleanVar(value=True)

        tree_frame = ttk.Frame(win)
        tree_frame.pack(fill="both", expand=True, padx=6, pady=4)
        cols = ("ip", "status", "ms", "fails", "last_ok")
        tree = ttk.Treeview(tree_frame, columns=cols, show="headings", height=14)
        for c, w, t in (("ip", 150, "IP"), ("status", 90, "Статус"),
                        ("ms", 80, "Отклик"), ("fails", 70, "Сбоев"),
                        ("last_ok", 160, "Последний успех")):
            tree.heading(c, text=t)
            tree.column(c, width=w, anchor="w")
        sb = ttk.Scrollbar(tree_frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=sb.set)
        tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        # Тэги для подсветки
        tree.tag_configure("up", foreground="#1a7f37")
        tree.tag_configure("down", foreground="#b00")

        # Заполняем строки из self.rtn_ips
        state = {}  # ip -> {fails, last_ok}
        for e in getattr(self, "rtn_ips", []):
            ip = e["ip"]
            tree.insert("", "end", iid=ip, values=(ip, "?", "-", 0, "-"), tags=("up",))
            state[ip] = {"fails": 0, "last_ok": "-", "was_up": None}

        def worker():
            import time as _time
            while running_var.get() and win.winfo_exists():
                for ip in list(state.keys()):
                    if not running_var.get() or not win.winfo_exists():
                        break
                    alive, ms = ping_rtn(ip)
                    st = state[ip]
                    now = datetime.now().strftime("%H:%M:%S")
                    if alive:
                        if st["was_up"] is False:
                            # Восстановление
                            try: winsound.Beep(1500, 150)
                            except Exception: pass
                        st["was_up"] = True
                        st["fails"] = 0
                        st["last_ok"] = now
                        tag = "up"
                        status_txt = "ЖИВ"
                    else:
                        if st["was_up"] is not False and st["was_up"] is not None:
                            # Переход в падение
                            if sound_var.get():
                                try: winsound.Beep(440, 600)
                                except Exception: pass
                        st["was_up"] = False
                        st["fails"] += 1
                        tag = "down"
                        status_txt = "УПАЛ"
                    try:
                        if win.winfo_exists():
                            tree.item(ip, values=(ip, status_txt, ms if alive else "-",
                                                   st["fails"], st["last_ok"]), tags=(tag,))
                    except Exception:
                        pass
                # Ждём интервал, но с возможностью раннего выхода
                for _ in range(int(interval_var.get()) * 10):
                    if not running_var.get() or not win.winfo_exists():
                        break
                    _time.sleep(0.1)

        def toggle():
            if running_var.get():
                running_var.set(False)
                btn_toggle.config(text="Старт")
            else:
                running_var.set(True)
                btn_toggle.config(text="Стоп")
                threading.Thread(target=worker, daemon=True).start()

        btn_toggle = ttk.Button(top, text="Стоп", command=toggle)
        btn_toggle.pack(side="left", padx=8)

        def on_close():
            running_var.set(False)
            win.destroy()
        win.protocol("WM_DELETE_WINDOW", on_close)

        if state:
            threading.Thread(target=worker, daemon=True).start()
        else:
            ttk.Label(win, text="Список RTN пуст — сначала выполните скан или «Обновить список».",
                      foreground="gray").pack(padx=8, pady=8)

    def rtn_radio_probe(self):
        """Автоопределение радио-параметров выбранного RTN через SSH (plink).
        Подключается, перебирает команды, показывает RSL/модуляцию/частоту
        и сырой вывод рабочих команд."""
        ip = self._rtn_selected_ip()
        if not ip:
            return
        root = get_weblct_root()
        user, password = read_rtn_credentials(root) if root else (None, None)
        if not user or not password:
            messagebox.showwarning("NetProbe",
                "Не найдены учётные данные RTN в config.txt.\n"
                "Заполните RTN_ACCOUNT_1=описание|логин|пароль")
            return
        if not find_plink():
            messagebox.showwarning("NetProbe",
                "Не найден plink.exe (PuTTY).\n"
                "Установите PuTTY в C:\\Program Files\\PuTTY\\")
            return
        # Окно с результатами
        win = tk.Toplevel(self)
        win.title(f"Радио-параметры {ip}")
        win.geometry("780x560")
        ttk.Label(win, text=f"Автоопрос RTN {ip} (SSH {user}@{ip})",
                  font=("", 10, "bold")).pack(pady=6)
        status_lbl = ttk.Label(win, text="подключение...", foreground="gray")
        status_lbl.pack()
        txt = tk.Text(win, wrap="none", font=("Consolas", 10), height=24)
        txt.pack(fill="both", expand=True, padx=8, pady=6)
        sb = ttk.Scrollbar(txt, command=txt.yview)
        sb.pack(side="right", fill="y")
        txt["yscrollcommand"] = sb.set

        def work():
            status_lbl.config(text="идёт опрос (это займёт ~30 сек)...")
            txt.delete("1.0", "end")
            txt.insert("end", f"=== Автоопрос {ip} ===\n\n")
            res = probe_rtn_radio(ip, user, password, log=self.log)
            # Параметры
            txt.insert("end", "=== Найденные параметры ===\n")
            for k, label in (("rsl", "RSL (уровень приёма)"),
                             ("tx_power", "Мощность передачи"),
                             ("modulation", "Модуляция"),
                             ("frequency", "Частота")):
                v = res.get(k)
                txt.insert("end", f"  {label}: {v if v else '— (не найдено)'}\n")
            txt.insert("end", f"\n=== Рабочие команды: {', '.join(res.get('worked_commands', [])) or 'нет'} ===\n")
            # Сырой вывод рабочих команд
            for cmd, out in res.get("raw", {}).items():
                txt.insert("end", f"\n--- {cmd} ---\n{out[:3000]}\n")
            status_lbl.config(text="готово", foreground="#1a7f37")
        threading.Thread(target=work, daemon=True).start()

    def rtn_telnet(self):
        """Открыть Telnet к выбранному RTN."""
        ip = self._rtn_selected_ip()
        if not ip:
            return
        telnet_to_rtn(ip, log=self.log)

    def rtn_backup_config(self):
        """Сохранить конфиг выбранного RTN через SSH (display current-configuration)."""
        ip = self._rtn_selected_ip()
        if not ip:
            return
        root = get_weblct_root()
        user, password = read_rtn_credentials(root) if root else (None, None)
        if not user or not password:
            messagebox.showwarning("NetProbe",
                "Не найдены учётные данные RTN в config.txt.")
            return
        if not find_plink():
            messagebox.showwarning("NetProbe", "Не найден plink.exe (PuTTY).")
            return
        self.log(f"[RTN] резервное копирование конфига {ip}...")
        backup_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "backups")
        if getattr(sys, "frozen", False):
            backup_dir = os.path.join(os.path.dirname(sys.executable), "backups")
        def work():
            f = backup_rtn_config(ip, user, password, log=self.log, backup_dir=backup_dir)
            if f:
                messagebox.showinfo("NetProbe", f"Конфиг сохранён:\n{f}")
        threading.Thread(target=work, daemon=True).start()

    def rtn_save_list(self):
        """Сохранить список найденных RTN в файл."""
        if not self.rtn_ips:
            messagebox.showinfo("NetProbe", "Список RTN пуст — сначала выполните скан.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".txt", initialfile="rtn-list.txt",
            filetypes=[("Text", "*.txt"), ("All", "*.*")],
            title="Сохранить список RTN")
        if not path:
            return
        ips = [e["ip"] for e in self.rtn_ips]
        save_rtn_list(ips, path, log=self.log)

    def rtn_load_list(self):
        """Загрузить список RTN из файла."""
        path = filedialog.askopenfilename(
            filetypes=[("Text", "*.txt"), ("All", "*.*")],
            title="Загрузить список RTN")
        if not path:
            return
        ips = load_rtn_list(path, log=self.log)
        self.rtn_ips = [{"ip": ip, "source": "файл"} for ip in ips]
        self._rtn_update_combo()

    def _done(self):
        self.btn["state"] = "normal"
        self.btn_stop["state"] = "disabled"
        self.status["text"] = "готово"
        # После скана автоматически обновляем список RTN (найденные IP).
        try:
            self.rtn_refresh()
        except Exception:
            pass


if __name__ == "__main__":
    App().mainloop()
