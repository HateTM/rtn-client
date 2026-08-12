#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import time
import xml.etree.ElementTree as ET

import requests
import uvicorn
from fastapi import FastAPI, HTTPException
from netmiko import ConnectHandler, NetmikoTimeoutException
from pydantic import BaseModel
from scapy.all import ARP, IP, Ether, sniff, srp
from scapy.contrib.ospf import OSPF_Hdr

app = FastAPI()
WEBLCT_PORT = 13443
FAIL_MARKERS = ("not recognized", "unrecognized", "invalid", "error:")

# Отключаем предупреждения о небезопасном HTTPS
requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)


class DeviceConfig(BaseModel):
    ip: str
    username: str = "admin"
    password: str = ""
    proxy_url: str | None = None
    jump_host: str | None = None


class RTNClient:
    def __init__(
        self, ip: str, username: str, password: str, proxy_url=None, jump_host=None
    ):
        self.ip = ip
        self.device = {
            "device_type": "huawei",
            "host": ip,
            "username": username,
            "password": password,
            "port": 22,
            "timeout": 15,
        }
        if proxy_url:
            self.device["proxy"] = proxy_url
        if jump_host:
            m = re.match(r"(?:([^@]+)@)?([^:]+)(?::(\d+))?", jump_host)
            if m:
                self.device["jump"] = {
                    "host": m.group(2),
                    "username": m.group(1) or "admin",
                    "port": int(m.group(3) or 22),
                }

    def execute(self, command: str) -> str:
        with ConnectHandler(**self.device) as ssh:
            return ssh.send_command(
                command, read_timeout=15, strip_prompt=True, strip_command=True
            )
    def get_lldp_neighbors(self) -> str:
        return self.execute("display lldp neighbor brief")


@app.post("/probe")
def api_probe(cfg: DeviceConfig):
    return probe_rtn_radio(
        RTNClient(
            cfg.ip,
            cfg.username,
            cfg.password,
            proxy_url=cfg.proxy_url,
            jump_host=cfg.jump_host,
        )
    )


@app.get("/find_devices")
def api_find_devices(
    root: str,
    host: str = "localhost",
    username: str = "admin",
    password: str = "Changeme_123",
):
    session = requests.Session()
    session.verify = False
    session.headers.update(
        {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
            "Connection": "keep-alive",
            "Referer": f"https://{host}:{WEBLCT_PORT}/weblct/page/login.html",
            "Origin": f"https://{host}:{WEBLCT_PORT}",
        }
    )

    try:
        # 1. Принудительный логаут
        try:
            session.get(
                f"https://{host}:{WEBLCT_PORT}/weblct/TSLogoutServlet", timeout=2
            )
        except requests.RequestException as e:
            print(f"DEBUG: Logout failed: {e}")

        print("DEBUG: Starting login process...")
        # 2. Логин
        data = {"txtname": username, "txtpassword": password}
        resp = session.post(
            f"https://{host}:{WEBLCT_PORT}/weblct/TSLoginCheck", data=data, timeout=5
        )
        print(f"DEBUG: TSLoginCheck status: {resp.status_code}")
        print(f"DEBUG: TSLoginCheck response: {resp.text[:500]}")
        print(f"DEBUG: Cookies after login: {session.cookies.get_dict()}")
        # 3. Логин
        data = {
            "txtname_show": "",
            "txtname": username,
            "txtpassword_show": "",
            "txtpassword": password,
            "txtverifycode": "",
            "submitbtn": "Login"
        }
        resp = session.post(
            f"https://{host}:{WEBLCT_PORT}/weblct/TSLoginCheck", data=data, timeout=5
        )
        time.sleep(2)

        # 3. Получение списка (имитируем поведение браузера)
        # Сначала посещаем nelist.html (как в перехваченных запросах)
        session.get(f"https://{host}:{WEBLCT_PORT}/weblct/page/nelist.html", timeout=5)

        # Устанавливаем правильный Referer для запроса к API
        session.headers.update({"Referer": f"https://{host}:{WEBLCT_PORT}/weblct/page/nelist.html"})
        # Выполняем POST и разрешаем редиректы
        # Возвращаем POST, так как 405 говорит, что GET запрещен
        resp = session.post(f"https://{host}:{WEBLCT_PORT}/weblct/neListServlet?sfid=280&flag=1", timeout=5, allow_redirects=True)
        print(f"DEBUG: WebLCT Response (neListServlet) status: {resp.status_code}")
        print(f"DEBUG: WebLCT Cookies after request: {session.cookies.get_dict()}")
        body = resp.text
        print(f"DEBUG: WebLCT Response (neListServlet) body: {body[:1000]}")
        if not body.strip():
            raise HTTPException(
                status_code=500,
                detail="WebLCT returned empty response from neListServlet",
            )
        # WebLCT возвращает XML, где устройства упакованы в 'row-params'
        # Нам нужно найти элементы 'param' с именами 'devip' и 'name'
        root_elem = ET.fromstring(body)
        out = []
        for row in root_elem.findall(".//row-params"):
            item = {}
            for param in row.findall("param"):
                name = param.get("name")
                value = param.get("value")
                if name and value:
                    item[name] = value
            if item.get("neGWAddress"):
                out.append({"ip": item["neGWAddress"], "name": item.get("neName", "Unknown")})
        print(f"DEBUG: Found {len(out)} devices")
        return out
    except Exception as e:  # noqa: BLE001
        import traceback

        print(f"DEBUG: Critical error: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=str(e))


def probe_rtn_radio(client: RTNClient) -> dict:
    result = {
        "rsl": None,
        "modulation": None,
        "frequency": None,
        "tx_power": None,
        "worked_commands": [],
    }
    for cmd in ["display radio", "display rfunit"]:
        try:
            out = client.execute(cmd)
        except Exception as e:  # noqa: BLE001
            print(f"DEBUG: Command execution failed: {e}")
            continue
        if any(marker in out.lower() for marker in FAIL_MARKERS):
            continue
        result["worked_commands"].append(cmd)
        for k, p in {
            "rsl": r"rsl[^\d-]*(-?\d+\.?\d*)",
            "modulation": r"mod[^\d]*(\d+\w+)",
        }.items():
            if result[k] is None and (m := re.search(p, out, re.IGNORECASE)):
                result[k] = m.group(1)
    return result


@app.post("/get_lldp")
def api_get_lldp(cfg: DeviceConfig):
    client = RTNClient(
        cfg.ip,
        cfg.username,
        cfg.password,
        proxy_url=cfg.proxy_url,
        jump_host=cfg.jump_host,
    )
    try:
        return {"lldp_neighbors": client.get_lldp_neighbors()}
    except NetmikoTimeoutException:
        return {"error": "Device unreachable (timeout)", "ip": cfg.ip}
    except Exception as e:  # noqa: BLE001
        return {"error": str(e), "ip": cfg.ip}

@app.get("/scan_ospf_passive")
def api_scan_ospf_passive(timeout: int = 30):
    """Пассивно слушает OSPF Hello-пакеты в течение timeout секунд."""
    neighbors = set()
    def packet_callback(pkt):
        # Логируем все приходящие пакеты для отладки
        if pkt.haslayer(IP):
            print(f"DEBUG: Packet received from {pkt[IP].src} (Protocol: {pkt[IP].proto})")
        if pkt.haslayer(OSPF_Hdr) and pkt.haslayer(IP):
            print(f"DEBUG: OSPF Packet detected from {pkt[IP].src}")
            neighbors.add(pkt[IP].src)

    # Фильтр: протокол 89 (OSPF)
    print(f"DEBUG: Starting passive sniff for {timeout}s...")
    sniff(filter="ip proto 89", prn=packet_callback, timeout=timeout, store=0)
    print(f"DEBUG: Sniff finished. Found neighbors: {neighbors}")
    return {"neighbors": list(neighbors)}
def api_scan_default():
    """Сканирует дефолтную подсеть 129.0.0.0/16."""
    return scan_network("129.0.0.0/16")

@app.post("/scan_ospf")
def api_scan_ospf(cfg: DeviceConfig):
    """Опрашивает OSPF соседей на устройстве."""
    client = RTNClient(
        cfg.ip, cfg.username, cfg.password,
        proxy_url=cfg.proxy_url, jump_host=cfg.jump_host
    )
    out = client.execute("display ospf peer brief")
    ips = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', out)
    return {"neighbors": list(set(ips))}

def scan_network(ip_range: str) -> list[dict]:
    """Сканирует сеть ARP-запросами."""
    try:
        arp = ARP(pdst=ip_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        result = srp(packet, timeout=3, verbose=0)[0]
        found = []
        for _, received in result:
            found.append({"ip": received.psrc, "mac": received.hwsrc})
        return {"network": ip_range, "found": found}
    except Exception as e:  # noqa: BLE001
        return {"error": str(e)}


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("serve")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=8000)
    args = ap.parse_args()
    if args.cmd == "serve":
        uvicorn.run(app, host=args.host, port=args.port)
