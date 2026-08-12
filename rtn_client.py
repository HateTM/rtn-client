#!/usr/bin/env python3
from __future__ import annotations

import argparse
import http.cookiejar
import json as _json
import re
import ssl
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

import uvicorn
from fastapi import FastAPI, HTTPException
from netmiko import ConnectHandler
from pydantic import BaseModel

app = FastAPI()
WEBLCT_PORT = 13443
FAIL_MARKERS = ("not recognized", "unrecognized", "invalid", "error:")

class DeviceConfig(BaseModel):
    ip: str; username: str = "admin"; password: str = ""; proxy_url: str | None = None; jump_host: str | None = None

class RTNClient:
    def __init__(self, ip: str, username: str, password: str, proxy_url=None, jump_host=None):
        self.ip = ip
        self.device = {"device_type": "huawei", "host": ip, "username": username, "password": password, "port": 22, "timeout": 15}
        if proxy_url: self.device["proxy"] = proxy_url
        if jump_host:
            m = re.match(r"(?:([^@]+)@)?([^:]+)(?::(\d+))?", jump_host)
            if m: self.device["jump"] = {"host": m.group(2), "username": m.group(1) or "admin", "port": int(m.group(3) or 22)}
    def execute(self, command: str) -> str:
        with ConnectHandler(**self.device) as ssh: return ssh.send_command(command, read_timeout=15, strip_prompt=True, strip_command=True)

@app.post("/probe")
def api_probe(cfg: DeviceConfig):
    return probe_rtn_radio(RTNClient(cfg.ip, cfg.username, cfg.password, proxy_url=cfg.proxy_url, jump_host=cfg.jump_host))

@app.get("/find_devices")
def api_find_devices(root: str, host: str = "localhost", username: str = "admin", password: str = "Changeme_123"):
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj), urllib.request.HTTPSHandler(context=ctx))
    try:
        opener.open(f"https://{host}:{WEBLCT_PORT}/weblct/page/login.html", timeout=5)
        data = urllib.parse.urlencode({"txtname": username, "txtpassword": password}).encode()
        opener.open(urllib.request.Request(f"https://{host}:{WEBLCT_PORT}/weblct/TSLoginCheck", data=data))
        req = urllib.request.Request(f"https://{host}:{WEBLCT_PORT}/weblct/neListServlet", data=b"")
        body = opener.open(req, timeout=5).read().decode("utf-8")
        print(f"DEBUG: WebLCT body response: {body[:500]}")
        out = []
        body = opener.open(req, timeout=5).read().decode("utf-8")
        out = []
        try:
            for elem in ET.fromstring(body).iter():
                if "devinfo" in elem.tag.lower() or elem.tag.lower().endswith("row"):
                    item = {c.tag.lower(): (c.text or "").strip() for c in elem}
                    if item.get("devip"): out.append({"ip": item["devip"], "name": item.get("name", "")})
        except Exception: # noqa: BLE001
            data = _json.loads(body)
            for item in (data if isinstance(data, list) else data.get("rows", [])):
                if item.get("devip"): out.append({"ip": item["devip"], "name": item.get("name", "")})
        return out
    except Exception as e:
        print(f"DEBUG: Exception in find_devices: {e}")
        raise HTTPException(status_code=500, detail=str(e)) # noqa: BLE001

def probe_rtn_radio(client: RTNClient) -> dict:
    result = {"rsl": None, "modulation": None, "frequency": None, "tx_power": None, "worked_commands": []}
    for cmd in ["display radio", "display rfunit"]:
        try: out = client.execute(cmd)
        except Exception: continue # noqa: BLE001, S112
        if any(marker in out.lower() for marker in FAIL_MARKERS): continue
        result["worked_commands"].append(cmd)
        for k, p in {"rsl": r"rsl[^\d-]*(-?\d+\.?\d*)", "modulation": r"mod[^\d]*(\d+\w+)"}.items():
            if result[k] is None and (m := re.search(p, out, re.IGNORECASE)): result[k] = m.group(1)
    return result

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("serve")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=8000)
    args = ap.parse_args()
    if args.cmd == "serve": uvicorn.run(app, host=args.host, port=args.port)
