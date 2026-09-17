import platform
import random
import time
from datetime import datetime, timezone

from sat_sa.normalizer import normalize

class DemoCollector:
    name = "Demo Simulator"
    def __init__(self):
        self.n = 0

    def collect(self):
        self.n += 1
        fail = self.n % 7 != 0
        if fail:
            msg = "Failed login for test account"
            code = "4625"
            level = "ERROR"
        else:
            msg = "Successful scheduled system event"
            code = "1000"
            level = "INFO"
        row = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "host": "DEMO-SOC-01",
            "source": "Demo Simulator",
            "event_code": code,
            "level": level,
            "category": "Authentication",
            "username": random.choice(["analyst", "service", "admin"]),
            "message": msg,
        }
        return normalize(row, "Demo Simulator")

class LinuxFileCollector:
    name = "Linux Log File"
    def __init__(self, path):
        self.path = path
        self.pos = 0

    def collect(self):
        try:
            with open(self.path, "r", errors="replace") as f:
                f.seek(self.pos)
                lines = f.readlines()
                self.pos = f.tell()
            if not lines:
                return None
            line = lines[-1].strip()
            return normalize({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "host": platform.node(),
                "source": self.path,
                "message": line,
                "level": "INFO",
            }, "Linux Log File")
        except Exception:
            return None

class WindowsEventCollector:
    name = "Windows Event Log"
    def __init__(self):
        self.handles = []
        self.last_ids = {}
        if platform.system() != "Windows":
            raise RuntimeError("Windows Event Log collection is available only on Windows.")
        import win32evtlog
        self.win32evtlog = win32evtlog
        for log_name in ["Security", "System", "Application"]:
            try:
                self.handles.append((log_name, win32evtlog.OpenEventLog(None, log_name)))
            except Exception:
                pass

    def collect(self):
        for log_name, handle in self.handles:
            flags = self.win32evtlog.EVENTLOG_BACKWARDS_READ | self.win32evtlog.EVENTLOG_SEQUENTIAL_READ
            try:
                records = self.win32evtlog.ReadEventLog(handle, flags, 0)
            except Exception:
                records = []
            for ev in records or []:
                eid = int(ev.EventID) & 0xFFFF
                key = (log_name, eid, str(ev.TimeGenerated))
                if key in self.last_ids:
                    continue
                self.last_ids[key] = True
                level = "ERROR" if eid in {4625, 4771, 4776} else "INFO"
                msg = " | ".join(str(x) for x in (ev.StringInserts or []))
                return normalize({
                    "timestamp": str(ev.TimeGenerated),
                    "host": str(ev.ComputerName or platform.node()),
                    "source": log_name,
                    "event_code": str(eid),
                    "level": level,
                    "category": "Authentication" if eid in {4625, 4771, 4776} else log_name,
                    "message": msg or f"Windows Event ID {eid}",
                }, "Windows Event Log")
        return None
