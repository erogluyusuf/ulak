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
            print(f"[!] Hata: rules.json yüklenemedi: {e}")
            return {"exit_codes": {}, "service_patterns": {}, "meta": {}}

    def send_desktop_notification(self, title, msg, severity):

        if severity not in ["high", "critical"]:
            return
        try:
            icon = "error" if severity == "critical" else "warning"
            subprocess.run(['notify-send', '-u', 'critical', '-i', icon, title, msg])
        except:
            pass

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
                    "action": data.get("action", "Inspect the related service and system logs.")
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
            except:
                pass

        meta = self.rules.get("meta", {})
        final_risk_score = base_diagnosis["risk_score"]

        if uid == 0 and meta.get("asset_awareness", {}).get("enabled", False):
            multiplier = meta["asset_awareness"].get("rules", {}).get("root_user_multiplier", 1.0)
            final_risk_score = int(final_risk_score * multiplier)

        max_cap = meta.get("risk_engine", {}).get("risk_escalation", {}).get("max_risk_cap", 100)
        final_risk_score = min(final_risk_score, max_cap)
        base_diagnosis["risk_score"] = final_risk_score

        if final_risk_score >= 95:
            base_diagnosis["severity"] = "critical"
        elif final_risk_score >= 75:
            base_diagnosis["severity"] = "high"
        elif final_risk_score >= 40:
            base_diagnosis["severity"] = "medium"
        else:
            base_diagnosis["severity"] = "low"

        return base_diagnosis

    def print_event(self, cpu, data, size):
        event = self.b["events"].event(data)
        cmd = event.comm.decode()

        uid = getattr(event, 'uid', os.getuid())

        if event.exit_code == 0: return

        event_key = f"{cmd}_{event.exit_code}"
        now = time.time()
        if event_key in self.event_history and (now - self.event_history[event_key] < 60):
            return
        self.event_history[event_key] = now

        ignored = ["python3", "ollama", "docker", "handler.py", "systemd"]
        if any(x in cmd for x in ignored) or event.pid == os.getpid(): return

        diag = self.get_diagnosis(cmd, event.exit_code, event.pid, uid)

        report = {
            "who": f"PID: {event.pid} (UID: {uid})",
            "what": f"'Process '{cmd}' failed.",
            "where": "Kernel Space",
            "when": time.strftime('%Y-%m-%d %H:%M:%S'),
            "why": diag.get("diagnosis"),
            "severity": diag.get("severity"),
            "risk_score": diag.get("risk_score"),
            "category": diag.get("category"),
            "mitre_technique": diag.get("mitre"),
            "suggested_action": diag.get("action"),
            "raw_data": {
                "cmd": cmd, "pid": event.pid, "exit_code": event.exit_code, "source": diag.get("source")
            }
        }

        if report["risk_score"] >= 40:
            mitre_tag = f" [MITRE: {report['mitre_technique']}]" if report['mitre_technique'] else ""
            print(f"\n[!] ({report['severity'].upper()}): {cmd} | Skor: {report['risk_score']}{mitre_tag} | Neden: {report['why']}")

        try:
            requests.post(DASHBOARD_URL, json=report, timeout=1)
        except:
            pass

    def print_exec_event(self, cpu, data, size):
        event = self.b["exec_events"].event(data)
        caller = event.comm.decode('utf-8', 'replace')
        target = event.fname.decode('utf-8', 'replace')
        pcomm = event.pcomm.decode('utf-8', 'replace')
        uid = event.uid
        pid = event.pid
        ppid = event.ppid

        try:
            user_name = pwd.getpwuid(uid).pw_name
        except:
            user_name = f"UID:{uid}"

        ignored_targets = ["/usr/bin/ps", "/usr/sbin/iptables", "/usr/bin/runc", "/usr/bin/containerd", "/usr/bin/which", "/usr/lib/NetworkManager"]
        ignored_callers = ["python3", "ollama", "docker", "systemd", "handler.py", "firewalld", "nm-dispatcher", "grep", "awk", "sed", "sleep", "cat"]

        if any(x in target for x in ignored_targets) or any(x in caller for x in ignored_callers) or pid == os.getpid():
            return

        cmd_full = f"EXEC CHAIN: {pcomm}({ppid}) -> {caller}({pid}) -> {target}"

        diag = self.get_diagnosis(cmd_full, 0, pid, uid)

        if diag.get("risk_score", 0) >= 40:
            report = {
                "who": f"{user_name} (PID:{pid} | PPID:{ppid})",
                "what": f"Critical file execution: {target}",
                "where": "Kernel / Execve",
                "when": time.strftime('%Y-%m-%d %H:%M:%S'),
                "why": diag.get("diagnosis", "Suspicious execution detected."),
                "severity": diag.get("severity", "medium"),
                "risk_score": diag.get("risk_score", 50),
                "category": "execution",
                "mitre_technique": diag.get("mitre", "T1059 (Command and Scripting Interpreter)"),
                "suggested_action": diag.get("action", "Terminate process and verify authorization."),
                "raw_data": {
                    "cmd": cmd_full, "pid": pid, "exit_code": 0, "source": diag.get("source")
                }
            }

            print(f"\n[!] EXECUTION DETECTED ({report['severity'].upper()}):")
            print(f"    User : {user_name}")
            print(f"    Chain    : {pcomm}({ppid}) -> {caller}({pid}) -> {target}")
            print(f"    Scor      : {report['risk_score']}")

            try:
                requests.post(DASHBOARD_URL, json=report, timeout=1)
            except:
                pass

    def print_file_event(self, cpu, data, size):
        event = self.b["file_events"].event(data)
        filename = event.filename.decode('utf-8', 'replace')
        comm = event.comm.decode('utf-8', 'replace')
        uid = event.uid
        pid = event.pid

        ignored_files = ["pipe", "socket", "null", "tty", "pts", "random", "urandom"]
        if any(x in filename for x in ignored_files) or pid == os.getpid():
            return

        critical_paths = ["passwd", "shadow", "sudoers", "config", "rules.json", ".bashrc"]
        is_critical = any(cp in filename for cp in critical_paths)

        if is_critical:
            try:
                user_name = pwd.getpwuid(uid).pw_name
            except:
                user_name = f"UID:{uid}"

            report = {
                "who": f"{user_name} (PID:{pid})",
                "what": f"File Modification: {filename}",
                "where": "VFS / Write",
                "when": time.strftime('%Y-%m-%d %H:%M:%S'),
                "why": "Unauthorized change to sensitive system file.",
                "severity": "high",
                "risk_score": 85,
                "category": "file_integrity",
                "mitre_technique": "T1565 (Data Manipulation)",
                "suggested_action": "Verify file integrity and check process authority.",
                "raw_data": {
                    "cmd": comm, "filename": filename, "pid": pid, "uid": uid
                }
            }

            print(f"\n[!] FILE INTEGRITY ALERT (HIGH):")
            print(f"    User : {user_name}")
            print(f"    File : {filename}")
            print(f"    By   : {comm}")

            try:
                requests.post(DASHBOARD_URL, json=report, timeout=1)
            except:
                pass

    def run(self):
        path = os.path.join(os.path.dirname(__file__), "probe.c")
        with open(path, "r") as f:
            bpf_code = f.read()

        self.b = BPF(text=bpf_code)

        self.b.attach_kprobe(event="do_exit", fn_name="trace_do_exit")
        self.b["events"].open_perf_buffer(self.print_event)

        self.b["exec_events"].open_perf_buffer(self.print_exec_event)

        self.b.attach_kprobe(event="vfs_write", fn_name="trace_vfs_write_entry")
        self.b["file_events"].open_perf_buffer(self.print_file_event)

        print("\n" + "="*60)
        print(" ULAK EDR - TRIPLE ENGINE ACTIVE")
        print(" MONITORING: [DO_EXIT], [EXECVE], [VFS_WRITE]")
        print("="*60 + "\n")

        while True:
            try:
                self.b.perf_buffer_poll()
            except KeyboardInterrupt:
                sys.exit(0)

if __name__ == "__main__":
    UlakHandler().run()
