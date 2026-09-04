"""
entities.py — the simulated enterprise directory.

The monitored organisation is the Department of Computer Science and
Engineering, Obafemi Awolowo University, Ile-Ife: academic staff, technical and
laboratory staff, the departmental ICT unit, administrative staff, security, and
postgraduate researchers. Every person has realistic identity and asset metadata
(unit, role, workstation, IP, device, clearance, working hours) so that an
incident can be investigated the way an analyst would.

All of it is synthetic data for the prototype, but it is shaped like the real
thing so the investigation and simulation views have something concrete to work
with.
"""
from __future__ import annotations
from dataclasses import dataclass, asdict, field
from typing import Dict, List, Optional

ORG = "Obafemi Awolowo University, Ile-Ife"
DEPT = "Computer Science and Engineering"

# ---------------------------------------------------------------- categories
CATEGORIES = [
    "Academic Staff",
    "Technical Staff",
    "ICT Unit",
    "Administrative Staff",
    "Security",
    "Postgraduate Research",
]

# subnet per category — makes the network map legible
SUBNET = {
    "Academic Staff":       "10.21.10",
    "Technical Staff":      "10.21.20",
    "ICT Unit":             "10.21.30",
    "Administrative Staff": "10.21.40",
    "Security":             "10.21.50",
    "Postgraduate Research":"10.21.60",
}
HOST_PREFIX = {
    "Academic Staff": "CSE-ACAD", "Technical Staff": "CSE-TECH",
    "ICT Unit": "CSE-ICT", "Administrative Staff": "CSE-ADM",
    "Security": "CSE-SEC", "Postgraduate Research": "CSE-PG",
}

CLEARANCE_BY_CAT = {
    "Academic Staff": "Confidential",
    "Technical Staff": "Internal",
    "ICT Unit": "Restricted",
    "Administrative Staff": "Confidential",
    "Security": "Internal",
    "Postgraduate Research": "Internal",
}


@dataclass
class Entity:
    uid: str
    name: str
    username: str
    category: str
    role: str
    unit: str
    host: str
    ip: str
    mac: str
    device_id: str
    os: str
    manager: str
    clearance: str
    location: str
    joined: str
    normal_hours: str
    email: str
    phone: str
    # live control flags (set from the dashboard)
    isolated: bool = False
    traffic_paused: bool = False

    def to_json(self) -> Dict:
        return asdict(self)


# --------------------------------------------------------------- the roster
# (name, category, role, unit, office)
_ROSTER = [
    # ---- Academic staff (10) ----
    ("Adebayo Ogunleye",     "Academic Staff", "Professor & Head of Department", "Software Engineering Group", "Faculty Block · Room 201"),
    ("Folashade Adeniyi",    "Academic Staff", "Professor", "Computer Networks Group", "Faculty Block · Room 203"),
    ("Chinedu Okafor",       "Academic Staff", "Reader", "Artificial Intelligence Group", "Faculty Block · Room 205"),
    ("Yetunde Balogun",      "Academic Staff", "Senior Lecturer", "Information Security Group", "Faculty Block · Room 207"),
    ("Ibrahim Suleiman",     "Academic Staff", "Senior Lecturer", "Computer Architecture Group", "Faculty Block · Room 209"),
    ("Ngozi Eze",            "Academic Staff", "Lecturer I", "Software Engineering Group", "Faculty Block · Room 211"),
    ("Tunde Afolabi",        "Academic Staff", "Lecturer I", "Computer Networks Group", "Faculty Block · Room 213"),
    ("Aisha Mohammed",       "Academic Staff", "Lecturer II", "Artificial Intelligence Group", "Faculty Block · Room 215"),
    ("Emeka Nwachukwu",      "Academic Staff", "Lecturer II", "Information Security Group", "Faculty Block · Room 217"),
    ("Bisi Oyelaran",        "Academic Staff", "Assistant Lecturer", "Software Engineering Group", "Faculty Block · Room 219"),
    # ---- Technical / laboratory staff (6) ----
    ("Segun Adeyemi",        "Technical Staff", "Chief Technologist", "Hardware Laboratory", "Engineering Annex · Lab A"),
    ("Halima Bello",         "Technical Staff", "Principal Technologist", "Networks Laboratory", "Engineering Annex · Lab B"),
    ("Kunle Ajayi",          "Technical Staff", "Technologist I", "Software Laboratory", "Engineering Annex · Lab C"),
    ("Uche Obi",             "Technical Staff", "Technologist II", "Hardware Laboratory", "Engineering Annex · Lab A"),
    ("Titilayo Fashola",     "Technical Staff", "Laboratory Technician", "Software Laboratory", "Engineering Annex · Lab C"),
    ("Musa Danladi",         "Technical Staff", "Laboratory Technician", "Networks Laboratory", "Engineering Annex · Lab B"),
    # ---- ICT unit (5) ----
    ("Olumide Sanusi",       "ICT Unit", "Network Administrator", "Departmental ICT Unit", "ICT Centre · Server Room"),
    ("Fatima Yusuf",         "ICT Unit", "Systems Administrator", "Departmental ICT Unit", "ICT Centre · Room 4"),
    ("Damilare Oyetunde",    "ICT Unit", "Database Administrator", "Departmental ICT Unit", "ICT Centre · Room 5"),
    ("Grace Attah",          "ICT Unit", "ICT Support Officer", "Departmental ICT Unit", "ICT Centre · Helpdesk"),
    ("Rotimi Adegoke",       "ICT Unit", "Web & Portal Officer", "Departmental ICT Unit", "ICT Centre · Room 6"),
    # ---- Administrative staff (4) ----
    ("Modupe Ilesanmi",      "Administrative Staff", "Departmental Secretary", "Departmental Office", "Faculty Block · Room 101"),
    ("Peter Agbaje",         "Administrative Staff", "Administrative Officer", "Departmental Office", "Faculty Block · Room 103"),
    ("Zainab Lawal",         "Administrative Staff", "Examinations Officer", "Examinations Unit", "Faculty Block · Room 105"),
    ("Samuel Etim",          "Administrative Staff", "Accounts Clerk", "Bursary Liaison", "Faculty Block · Room 107"),
    # ---- Security (3) ----
    ("Abdulrahman Garba",    "Security", "Chief Security Officer", "Campus Security", "Security Post · Gate 2"),
    ("Chioma Nnaji",         "Security", "Security Officer", "Campus Security", "Security Post · Gate 2"),
    ("Bala Shehu",           "Security", "CCTV Control Operator", "Campus Security", "Security Post · Control Room"),
    # ---- Postgraduate research (2) ----
    ("Oluwaseun Adeleke",    "Postgraduate Research", "PhD Researcher", "Information Security Group", "Postgraduate Lab · Desk 12"),
    ("Kelechi Ugochukwu",    "Postgraduate Research", "MSc Research Assistant", "Artificial Intelligence Group", "Postgraduate Lab · Desk 7"),
]

# Technical people run Linux (so the remote shell is meaningful); office and
# security staff run Windows; a few academics run macOS.
_OS_BY_CAT = {
    "ICT Unit":             ["Ubuntu 22.04 LTS", "Ubuntu 24.04 LTS", "Debian 12"],
    "Technical Staff":      ["Ubuntu 22.04 LTS", "Fedora 40", "Ubuntu 24.04 LTS"],
    "Postgraduate Research":["Ubuntu 22.04 LTS", "Pop!_OS 22.04"],
    "Academic Staff":       ["Ubuntu 22.04 LTS", "macOS 14 Sonoma", "Windows 11 Pro"],
    "Administrative Staff": ["Windows 11 Pro", "Windows 10 Pro"],
    "Security":             ["Windows 10 Pro", "Ubuntu 22.04 LTS"],
}
_HOURS_POOL = ["08:00-16:00", "08:30-16:30", "09:00-17:00", "07:30-15:30", "10:00-18:00"]

DIRECTORY: Dict[str, Entity] = {}


def _username(name: str) -> str:
    first, last = name.split()[0], name.split()[-1]
    return (first[0] + last).lower()


def _build():
    counters: Dict[str, int] = {}
    for idx, (name, cat, role, unit, office) in enumerate(_ROSTER):
        n = counters.get(cat, 0) + 1
        counters[cat] = n
        uname = _username(name)
        host = f"{HOST_PREFIX[cat]}-{n:02d}"
        ip = f"{SUBNET[cat]}.{20 + n}"
        mac = "5C:F9:{:02X}:{:02X}:{:02X}:{:02X}".format(
            (idx * 37) % 256, (idx * 91 + 13) % 256, (idx * 53 + 7) % 256, (idx * 17 + 41) % 256)
        # the HOD manages academics; unit heads manage their own people
        manager = ("—" if role.startswith("Professor & Head")
                   else "Adebayo Ogunleye" if cat == "Academic Staff"
                   else "Segun Adeyemi" if cat == "Technical Staff"
                   else "Olumide Sanusi" if cat == "ICT Unit"
                   else "Modupe Ilesanmi" if cat == "Administrative Staff"
                   else "Abdulrahman Garba" if cat == "Security"
                   else "Yetunde Balogun")
        e = Entity(
            uid="user:" + uname, name=name, username=uname, category=cat, role=role,
            unit=unit, host=host, ip=ip, mac=mac,
            device_id=f"OAU-CSE-{1000 + idx * 7}",
            os=_OS_BY_CAT[cat][idx % len(_OS_BY_CAT[cat])],
            manager=manager,
            clearance="Restricted" if role.startswith("Professor & Head") else CLEARANCE_BY_CAT[cat],
            location=office,
            joined=f"{2005 + (idx * 3) % 19}-{1 + (idx * 5) % 12:02d}",
            normal_hours=_HOURS_POOL[idx % len(_HOURS_POOL)],
            email=f"{uname}@oauife.edu.ng",
            phone=f"+234 80{(idx * 7) % 10}{(idx * 3) % 10} {200 + idx:03d} {4000 + idx * 11:04d}",
        )
        DIRECTORY[e.uid] = e


_build()

# The user the built-in attack scenarios focus on: a systems administrator, the
# most consequential insider in a university department (broad access, and a
# plausible motive story for the demo).
TARGET_UID = "user:fyusuf"

# an external address the exfiltration scenario talks to
EXFIL_DST = "185.220.101.47"
EXFIL_DST_GEO = "Unattributed hosting/VPS range (no ASN reputation)"


# ------------------------------------------------------------------ accessors
def get(uid: str) -> Optional[Entity]:
    return DIRECTORY.get(uid)


def all_entities() -> List[Entity]:
    return list(DIRECTORY.values())


def uids() -> List[str]:
    return list(DIRECTORY.keys())


def by_category(cat: str) -> List[Entity]:
    return [e for e in DIRECTORY.values() if e.category == cat]


def categories() -> List[str]:
    return CATEGORIES


def set_isolated(uid: str, value: bool) -> bool:
    e = DIRECTORY.get(uid)
    if not e:
        return False
    e.isolated = value
    return True


def set_paused(uid: str, value: bool) -> bool:
    e = DIRECTORY.get(uid)
    if not e:
        return False
    e.traffic_paused = value
    return True
