import importlib.util as u, ipaddress, sys

s = u.spec_from_file_location("np", "netprobe.py")
m = u.module_from_spec(s)
s.loader.exec_module(m)

print("admin:", m.is_admin(), "npcap:", m.has_npcap(), "scapy:", m.SCAPY)
ifs = m.list_ifaces()
for i, d in enumerate(ifs):
    print(i, d["name"], "|", d["label"])
tgt = next((d for d in ifs if d["ips"] and not d["ips"][0].startswith("169.254")), ifs[0])
print("target:", tgt["name"], tgt["ips"])

p = m.ProbeND(tgt, lambda x: print("LOG:", x), sniff_time=8, mask=26,
              allow_temp_ip=False, gw_probe=False)
p.passive()
print("seen:", p.seen)
print("names:", p.names)
print("roles:", p.roles)
print("bcast:", p.bcast_dst)
gw = [i for i in m.arp_table()]
print("arp table:", gw[:10])
if p.seen:
    ip = sorted(p.seen)[0]
    net = ipaddress.ip_network(f"{ip}/26", strict=False)
    print("SendARP test to", str(net.network_address + 1), "->", m.send_arp(str(net.network_address + 1)))
