import os
import sys
import json
import re
import time
import requests
import subprocess
import pwd
from bcc import BPF

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from analyzer.engine import NativeAIAnalyzer

RULES_PATH = os.path.join(os.path.dirname(__file__), "../../config/rules.json")
DASHBOARD_URL = "http://localhost:8000/report"

class UlakHandler:
    def __init__(self):

        self.analyzer = NativeAIAnalyzer(model="tinyllama")
        self.rules = self.load_rules()
        self.b = None
        self.event_history = {}

    def load_rules(self):

        try:
            if os.path.exists(RULES_PATH):
                with open(RULES_PATH, "r", encoding="utf-8") as f:
                    return json.load(f)
            return {"exit_codes": {}, "service_patterns": {}, "meta": {}}
        except Exception as e:
            print(f"[!] Error: rules.json could not be loaded: {e}")
            return {"exit_codes": {}, "service_patterns": {}, "meta": {}}

    def get_diagnosis(self, cmd, exit_code, pid, uid):

        base_diagnosis = {
            "source": "Heuristic Engine",
            "diagnosis": "Unknown Error",
            "severity": "low",
            "risk_score": 10,
            "category": "general",
            "mitre": None,
            "action": "Check system logs manually."
        }

        matched = False

        for name, data in self.rules.get("service_patterns", {}).items():
            regex_str = data.get("regex", "")
            if regex_str and re.search(regex_str, cmd, re.IGNORECASE):
                base_diagnosis.update({
                    "source": f"Rules ({name})",
                    "diagnosis": data.get("description", "Critical service failure."),
                    "severity": data.get("severity", "medium"),
                    "risk_score": data.get("risk_score", 50),
                    "category": data.get("category", "security"),
                    "mitre": data.get("mitre", None),
                    "action": data.get("action", "Inspect the related service.")
                })
                matched = True
                break

        if not matched:
            code_str = str(exit_code)
            if code_str in self.rules.get("exit_codes", {}):
                rule_data = self.rules["exit_codes"][code_str]
                base_diagnosis.update({
                    "source": "Local Dictionary",
                    "diagnosis": rule_data.get("description", "System Fault"),
                    "severity": rule_data.get("severity", "low"),
                    "risk_score": rule_data.get("risk_score", 30),
                    "category": rule_data.get("category", "system")
                })
                matched = True

        if not matched:
            try:
                ai_report = self.analyzer.analyze_event(cmd, exit_code, pid)
                base_diagnosis["diagnosis"] = ai_report.get("diagnosis", "Heuristic analysis failed.")
                base_diagnosis["action"] = ai_report.get("action", "Manual investigation required.")
                base_diagnosis["risk_score"] = 20
            except: pass

        meta = self.rules.get("meta", {})
        final_score = base_diagnosis["risk_score"]
        if uid == 0 and meta.get("asset_awareness", {}).get("enabled", False):
            multiplier = meta["asset_awareness"].get("rules", {}).get("root_user_multiplier", 1.0)
            final_score = int(final_score * multiplier)

        max_cap = meta.get("risk_engine", {}).get("risk_escalation", {}).get("max_risk_cap", 100)
        base_diagnosis["risk_score"] = min(final_score, max_cap)

        if base_diagnosis["risk_score"] >= 95: base_diagnosis["severity"] = "critical"
        elif base_diagnosis["risk_score"] >= 75: base_diagnosis["severity"] = "high"
        elif base_diagnosis["risk_score"] >= 40: base_diagnosis["severity"] = "medium"
        else: base_diagnosis["severity"] = "low"

        return base_diagnosis

    def print_event(self, cpu, data, size):

        event = self.b["events"].event(data)
        cmd = event.comm.decode()
        uid = getattr(event, 'uid', os.getuid())
        if event.exit_code == 0: return

        event_key = f"{cmd}_{event.exit_code}"
        now = time.time()
        if event_key in self.event_history and (now - self.event_history[event_key] < 60): return
        self.event_history[event_key] = now

        diag = self.get_diagnosis(cmd, event.exit_code, event.pid, uid)
        report = {
            "who": f"PID: {event.pid} (UID: {uid})",
            "what": f"Process '{cmd}' failed.",
            "where": "Kernel Space / Exit",
            "when": time.strftime('%Y-%m-%d %H:%M:%S'),
            "why": diag["diagnosis"],
            "severity": diag["severity"],
            "risk_score": diag["risk_score"],
            "category": diag["category"],
            "raw_data": {"cmd": cmd, "pid": event.pid, "exit_code": event.exit_code}
        }

        if report["risk_score"] >= 40:
            print(f"\n[!] ALERT: {cmd} | Score: {report['risk_score']} | Reason: {report['why']}")
            try: requests.post(DASHBOARD_URL, json=report, timeout=1)
            except: pass

    def print_exec_event(self, cpu, data, size):

        event = self.b["exec_events"].event(data)
        caller, target = event.comm.decode(), event.fname.decode()

        ignored = [
            "python3", "ollama", "docker", "systemd", "handler.py",
            "cpuUsage.sh", "plasma_waitforname", "bwrap", "glycin-svg",
            "/usr/bin/cat", "/usr/bin/sed", "/usr/bin/ps",
            "/usr/bin/which", "/usr/bin/sleep", "/usr/bin/users",
            "/bin/sh", "/bin/bash", "/usr/bin/grep", "/usr/bin/awk",
            "pkla-check-authorization", "revokefs-fuse", "fusermount3",
            "notify-send", "sudo", "gpg", "desktop-database.trigger",
            "update-desktop-database", "gtk-update-icon-cache",
            "update-mime-database", "/usr/bin/cp", "glycin-image-rs",
            "/proc/self/fd","adb", "pkill", "env", "bash"
            ]

        if any(x in target for x in ignored) or event.pid == os.getpid(): return

        try: user_name = pwd.getpwuid(event.uid).pw_name
        except: user_name = f"UID:{event.uid}"

        report = {
            "who": f"{user_name} (PID:{event.pid})",
            "what": f"Execution Detected: {target}",
            "where": "Kernel / Execve",
            "when": time.strftime('%Y-%m-%d %H:%M:%S'),
            "why": "Binary execution monitored.",
            "severity": "medium",
            "risk_score": 45,
            "category": "execution",
            "raw_data": {"cmd": target, "pid": event.pid, "uid": event.uid}
        }
        print(f"\n[!] EXECUTION: {user_name} executed {target}")
        try: requests.post(DASHBOARD_URL, json=report, timeout=1)
        except: pass

    def print_file_event(self, cpu, data, size):

        event = self.b["file_events"].event(data)
        filename, comm = event.filename.decode('utf-8', 'replace'), event.comm.decode()

        critical_paths = ["passwd", "shadow", "sudoers", "config", "rules.json", ".bashrc"]
        if not any(cp in filename for cp in critical_paths): return

        try: user_name = pwd.getpwuid(event.uid).pw_name
        except: user_name = f"UID:{event.uid}"

        report = {
            "who": f"{user_name} (PID:{event.pid})",
            "what": f"File Modified: {filename}",
            "where": "VFS / Write",
            "when": time.strftime('%Y-%m-%d %H:%M:%S'),
            "why": "Sensitive file integrity change detected.",
            "severity": "high",
            "risk_score": 85,
            "category": "file_integrity",
            "raw_data": {"filename": filename, "pid": event.pid, "uid": event.uid, "by": comm}
        }
        print(f"\n[!] FILE INTEGRITY ALERT: {user_name} modified {filename} via {comm}")
        try: requests.post(DASHBOARD_URL, json=report, timeout=1)
        except: pass

    def run(self):

        path = os.path.join(os.path.dirname(__file__), "probe.c")
        with open(path, "r") as f:
            bpf_code = f.read()

        self.b = BPF(text=bpf_code)

        self.b.attach_kprobe(event="do_exit", fn_name="trace_do_exit")
        self.b.attach_kprobe(event="vfs_write", fn_name="trace_vfs_write_entry")

        self.b["events"].open_perf_buffer(self.print_event)
        self.b["exec_events"].open_perf_buffer(self.print_exec_event)
        self.b["file_events"].open_perf_buffer(self.print_file_event)

        print("\n" + "="*60)
        print(" ULAK EDR - TRIPLE ENGINE ACTIVE (EXIT, EXEC, FIM)")
        print(" MONITORING: Kernel Space Syscalls")
        print("="*60 + "\n")

        while True:
            try:
                self.b.perf_buffer_poll()
            except KeyboardInterrupt:
                sys.exit(0)

if __name__ == "__main__":
    UlakHandler().run()
