import os
import sys
import json
import re
import time
import requests
import subprocess
from bcc import BPF

# Proje kök dizinini yola ekle
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from analyzer.engine import NativeAIAnalyzer

# Yapılandırma
RULES_PATH = os.path.join(os.path.dirname(__file__), "../../config/rules.json")
DASHBOARD_URL = "http://localhost:8000/report"

class UlakHandler:
    def __init__(self):
        self.analyzer = NativeAIAnalyzer(model="tinyllama")
        self.rules = self.load_rules()
        self.b = None
        self.event_history = {} # Yinelenen hataları susturmak için

    def load_rules(self):
        try:
            if os.path.exists(RULES_PATH):
                with open(RULES_PATH, "r") as f:
                    return json.load(f)
            return {"exit_codes": {}, "service_patterns": {}}
        except Exception as e:
            print(f"[!] Hata: rules.json yüklenemedi: {e}")
            return {"exit_codes": {}, "service_patterns": {}}

    def send_desktop_notification(self, title, msg, severity):
        """Kritiklik seviyesine göre OS bildirimi fırlatır."""
        # Sadece riskli durumlarda (medium/high/critical) bildirim gönder
        if severity not in ["high", "critical"]:
            return
        try:
            icon = "error" if severity == "critical" else "warning"
            subprocess.run(['notify-send', '-u', 'critical', '-i', icon, title, msg])
        except:
            pass

    def get_diagnosis(self, cmd, exit_code, pid):
        """Kurallar üzerinden teşhis koy ve skorları al."""
        # 1. Aşama: Servis Kalıpları (Örn: SSH, SQLi, OOM)
        for name, data in self.rules.get("service_patterns", {}).items():
            regex_str = data["regex"] if isinstance(data, dict) else str(data)
            if re.search(regex_str, cmd, re.IGNORECASE):
                return {
                    "source": f"Rules ({name})",
                    "diagnosis": data.get("description", "Kritik servis hatası."),
                    "action": data.get("action", "Logları inceleyin."),
                    "severity": data.get("severity", "medium"),
                    "risk_score": data.get("risk_score", 50),
                    "category": data.get("category", "security")
                }

        # 2. Aşama: Exit Codes
        code_str = str(exit_code)
        if code_str in self.rules.get("exit_codes", {}):
            return {
                "source": "Local Dictionary",
                "diagnosis": self.rules["exit_codes"][code_str],
                "severity": "low",
                "risk_score": 30,
                "category": "system"
            }

        return {"source": "AI", "diagnosis": "Bilinmeyen Hata", "severity": "low", "risk_score": 20}

    def print_event(self, cpu, data, size):
        event = self.b["events"].event(data)
        cmd = event.comm.decode()

        # --- AKILLI FİLTRELEME VE GÜRÜLTÜ ENGELLEME ---
        if event.exit_code == 0: return
        
        # Yinelenen Olay Kontrolü (Aynı komut ve kod için 60 sn bekle)
        event_key = f"{cmd}_{event.exit_code}"
        now = time.time()
        if event_key in self.event_history and (now - self.event_history[event_key] < 60):
            return
        self.event_history[event_key] = now

        # Süreç Filtreleme
        ignored = ["python3", "ollama", "docker", "curl", "handler.py", "systemd"]
        if any(x in cmd for x in ignored) or event.pid == os.getpid(): return
        # ----------------------------------------------

        diag = self.get_diagnosis(cmd, event.exit_code, event.pid)
        
        report = {
            "who": f"PID: {event.pid} (UID: {os.getuid()})",
            "what": f"'{cmd}' süreci başarısız oldu.",
            "where": "Kernel Space",
            "when": time.strftime('%Y-%m-%d %H:%M:%S'),
            "why": diag.get("diagnosis"),
            "severity": diag.get("severity", "low"),
            "risk_score": diag.get("risk_score", 20),
            "category": diag.get("category", "general"),
            "suggested_action": diag.get("action", "Gerekli izinleri kontrol edin."),
            "raw_data": {
                "cmd": cmd, "pid": event.pid, "exit_code": event.exit_code, "source": diag.get("source")
            }
        }

        # Konsol çıktısını sadece belirli risk üstünde ver (Gürültü kesme)
        if report["risk_score"] >= 40:
            print(f"\n[!] 5N1K TESPİTİ ({report['severity'].upper()}): {cmd} | Skor: {report['risk_score']}")
            self.send_desktop_notification(f"ULAK: {cmd} Hatası", report['why'], report['severity'])

        # Dashboard'a her zaman gönder
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

        print("\n" + "="*55)
        print(" ULAK AI SENSÖRÜ AKTİF - AKILLI FİLTRELEME AÇIK")
        print("="*55 + "\n")

        self.b["events"].open_perf_buffer(self.print_event)
        while True:
            try:
                self.b.perf_buffer_poll()
            except KeyboardInterrupt:
                sys.exit(0)

if __name__ == "__main__":
    UlakHandler().run()