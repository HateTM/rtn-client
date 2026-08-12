import ctypes
import ipaddress
import os
import re
import socket
import struct
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor

# Constants
BCAST_MAC = "ff:ff:ff:ff:ff:ff"
NO_WIN = 0x08000000
LISTEN_PORTS = [68, 67, 137, 138, 1900, 5353, 5355, 3702, 5678]
SSDP_MSEARCH = (
    b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
    b'MAN: "ssdp:discover"\r\nMX: 2\r\nST: upnp:rootdevice\r\n\r\n'
)


# Helper functions extracted from netprobe.py
def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def run_cmd(args):
    try:
        p = subprocess.run(args, capture_output=True, creationflags=NO_WIN)
    except Exception as e:
        return 1, repr(e)
    blob = p.stdout + p.stderr
    for enc in ("utf-8", "cp866", "cp1251"):
        try:
            return p.returncode, blob.decode(enc, errors="strict").strip()
        except UnicodeDecodeError:
            continue
    return p.returncode, blob.decode("cp866", errors="replace").strip()


def looks_local(ip):
    return not ip.startswith(("169.254.", "224.", "239.", "255.", "0."))


def send_arp(dst, src="0.0.0.0"):
    try:
        d = struct.unpack("<L", socket.inet_aton(dst))[0]
        s = struct.unpack("<L", socket.inet_aton(src))[0]
        buf = (ctypes.c_ubyte * 6)()
        ln = ctypes.c_ulong(6)
        if (
            ctypes.windll.iphlpapi.SendARP(d, s, ctypes.byref(buf), ctypes.byref(ln))
            == 0
            and ln.value == 6
        ):
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


def netsh_ipv4(ifd, verb, obj, *rest):
    rc, out = 1, ""
    for key in (ifd.get("name"), str(ifd.get("index", ""))):
        if not key:
            continue
        rc, out = run_cmd(
            ["netsh", "interface", "ipv4", verb, obj, f"name={key}", *rest]
        )
        if rc == 0:
            return rc, out
    return rc, out


def ip_set_static(ifd, ip, mask, gw=None, add=False):
    if add:
        return netsh_ipv4(ifd, "add", "address", ip, mask)
    return netsh_ipv4(ifd, "set", "address", "static", ip, mask, gw if gw else "none")


def ip_del(ifd, ip):
    return netsh_ipv4(ifd, "delete", "address", f"addr={ip}")


def ip_show(ifd):
    return netsh_ipv4(ifd, "show", "addresses")[1]


# BaseProbe class
class BaseProbe:
    def __init__(self, iface, log, sniff_time=25, mask=26):
        self.iface = iface
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
        self.roles = {}
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
                    nm = "".join(
                        chr(((ord(e[i]) - 65) << 4) | (ord(e[i + 1]) - 65))
                        for i in range(0, 32, 2)
                    ).strip()
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

    def cleanup(self):
        if self.temp_ip:
            rc, out = ip_del(self.iface, self.temp_ip)
            self.log(
                f"[*] временный адрес {self.temp_ip} снят с '{self.name}' ({'ok' if not rc else out})"
            )
            self.temp_ip = None


# ProbeND class (Copied logic)
class ProbeND(BaseProbe):
    def __init__(
        self, iface, log, sniff_time=25, mask=26, allow_temp_ip=True, gw_probe=False
    ):
        super().__init__(iface, log, sniff_time, mask)
        self.allow_temp_ip = allow_temp_ip
        self.gw_probe = gw_probe
        self.local_ips = [i for i in iface.get("ips", []) if ":" not in i]
        self.my_mac = (iface.get("mac") or "").lower()

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
                sp, dp = struct.unpack("!HH", b[ihl : ihl + 4])
                self.note_name(src, b[ihl + 8 :], sp, dp)
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
                grp = {
                    5353: "224.0.0.251",
                    5355: "224.0.0.252",
                    1900: "239.255.255.250",
                    3702: "239.255.255.250",
                }[port]
                for lip in self.local_ips or ["0.0.0.0"]:
                    try:
                        s.setsockopt(
                            socket.IPPROTO_IP,
                            socket.IP_ADD_MEMBERSHIP,
                            socket.inet_aton(grp) + socket.inet_aton(lip),
                        )
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
        self.log(
            f"[1] Портативный режим (без драйверов): слушаю {self.sniff_time} c..."
        )
        if not self.local_ips:
            self.log(
                "    у адаптера нет IPv4 — promisc-захват невозможен, только UDP-широковещание"
            )
        until = time.time() + self.sniff_time
        th = [threading.Thread(target=self._arp_poll, args=(until,), daemon=True)]
        for lip in self.local_ips:
            th.append(
                threading.Thread(target=self._raw_sniff, args=(lip, until), daemon=True)
            )
        for p in LISTEN_PORTS:
            th.append(
                threading.Thread(target=self._udp_listen, args=(p, until), daemon=True)
            )
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

    def _ensure_onlink(self, net):
        for ip in self.local_ips:
            if ipaddress.IPv4Address(ip) in net:
                return ip
        if not self.allow_temp_ip:
            self.log(
                "    ! нет адреса в этой подсети, а временный IP запрещён галкой — ARP-скан пропущен"
            )
            return None
        if not is_admin():
            self.log(
                "    ! нужны права администратора для назначения временного адреса"
            )
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
            if (mac and mac != self.my_mac) or re.search(
                r"Duplicate|Дубликат", txt, re.I
            ):
                self.log(f"    {cand} занят — пробую следующий")
                ip_del(self.iface, cand)
                continue
            self.temp_ip = cand
            self.log(
                f"[2b] на '{self.name}' временно добавлен {cand}/{net.prefixlen} (будет снят после скана)"
            )
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
            self.log(
                f"[3b] ARP недоступен (нет адреса в {net}) — ping-скан через маршрутизацию..."
            )
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
            self.log(
                "[3c] ICMP молчит — добиваю TCP-пробой (80/443/22/23/8080/445/502)..."
            )
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

    def scan(self, net_str: str):
        net = ipaddress.ip_network(net_str, strict=False)
        self.log(f"Запуск сканирования для {net}")
        self.passive()
        return self.sweep(net)
