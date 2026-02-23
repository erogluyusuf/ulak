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
        # AI Analiz motoru (Hafif model - TinyLlama)
        self.analyzer = NativeAIAnalyzer(model="tinyllama")
        self.rules = self.load_rules()
        self.b = None
        self.event_history = {} # Yinelenen hataları susturmak için

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
        """Kritiklik seviyesine göre OS bildirimi fırlatır."""
        if severity not in ["high", "critical"]:
            return
        try:
            icon = "error" if severity == "critical" else "warning"
            subprocess.run(['notify-send', '-u', 'critical', '-i', icon, title, msg])
        except:
            pass

    def get_diagnosis(self, cmd, exit_code, pid, uid):
        """Kurallar üzerinden teşhis koy ve YENİ RİSK MOTORUNU (v3.0) kullan."""
        
        base_diagnosis = {
            "source": "AI",
            "diagnosis": "Bilinmeyen Hata",
            "severity": "low",
            "risk_score": 10,
            "category": "general",
            "mitre": None,
            "action": "Sistem loglarını inceleyin."
        }

        matched = False

        # 1. Aşama: Servis Kalıpları ve Güvenlik İhlalleri
        for name, data in self.rules.get("service_patterns", {}).items():
            regex_str = data.get("regex", "")
            if regex_str and re.search(regex_str, cmd, re.IGNORECASE):
                base_diagnosis.update({
                    "source": f"Rules ({name})",
                    "diagnosis": data.get("description", "Kritik servis hatası."),
                    "severity": data.get("severity", "medium"),
                    "risk_score": data.get("risk_score", 50),
                    "category": data.get("category", "security"),
                    "mitre": data.get("mitre", None),
                    "action": data.get("action", "İlgili servisi kontrol edin.")
                })
                matched = True
                break

        # 2. Aşama: Standart Exit Codes (Eğer pattern bulunamadıysa)
        if not matched:
            code_str = str(exit_code)
            if code_str in self.rules.get("exit_codes", {}):
                rule_data = self.rules["exit_codes"][code_str]
                base_diagnosis.update({
                    "source": "Local Dictionary",
                    "diagnosis": rule_data.get("description", "Sistem Hatası"),
                    "severity": rule_data.get("severity", "low"),
                    "risk_score": rule_data.get("risk_score", 30),
                    "category": rule_data.get("category", "system")
                })
                matched = True

        # 3. Aşama: Hiçbir kurala uymazsa AI (TinyLlama) devreye girer
        if not matched:
            try:
                ai_report = self.analyzer.analyze_event(cmd, exit_code, pid)
                base_diagnosis["diagnosis"] = ai_report.get("diagnosis", "AI Analizi başarısız.")
                base_diagnosis["action"] = ai_report.get("action", "Manuel analiz gereklidir.")
                base_diagnosis["risk_score"] = 20
            except:
                pass

        # --- YENİ EKLENEN RİSK MOTORU VE VARLIK FARKINDALIĞI ---
        meta = self.rules.get("meta", {})
        final_risk_score = base_diagnosis["risk_score"]

        # Varlık Farkındalığı: İşlemi Root (UID 0) yaptıysa çarpanı uygula
        if uid == 0 and meta.get("asset_awareness", {}).get("enabled", False):
            multiplier = meta["asset_awareness"].get("rules", {}).get("root_user_multiplier", 1.0)
            final_risk_score = int(final_risk_score * multiplier)

        # Risk Skoru Sınırı (Max Cap - Örn: 100)
        max_cap = meta.get("risk_engine", {}).get("risk_escalation", {}).get("max_risk_cap", 100)
        final_risk_score = min(final_risk_score, max_cap)
        base_diagnosis["risk_score"] = final_risk_score

        # Puan yükseldiyse Severity'yi dinamik olarak güncelle
        if final_risk_score >= 95:
            base_diagnosis["severity"] = "critical"
        elif final_risk_score >= 75:
            base_diagnosis["severity"] = "high"
        elif final_risk_score >= 40:
            base_diagnosis["severity"] = "medium"
        else:
            base_diagnosis["severity"] = "low"
        # --------------------------------------------------------

        return base_diagnosis

    def print_event(self, cpu, data, size):
        event = self.b["events"].event(data)
        cmd = event.comm.decode()
        
        # Gerçek UID'yi eBPF'den alamadığımız senaryoda varsayılan işletim sistemi UID'sini alır
        uid = getattr(event, 'uid', os.getuid())

        # --- AKILLI FİLTRELEME VE GÜRÜLTÜ ENGELLEME ---
        if event.exit_code == 0: return
        
        # Yinelenen Olay Kontrolü (60 saniye kuralı)
        event_key = f"{cmd}_{event.exit_code}"
        now = time.time()
        if event_key in self.event_history and (now - self.event_history[event_key] < 60):
            return
        self.event_history[event_key] = now

        # Ulak'ın kendi süreçlerini filtrele
        ignored = ["python3", "ollama", "docker", "handler.py", "systemd"]
        if any(x in cmd for x in ignored) or event.pid == os.getpid(): return
        # ----------------------------------------------

        # Teşhis ve Risk Hesaplama fonksiyonunu çağır
        diag = self.get_diagnosis(cmd, event.exit_code, event.pid, uid)
        
        report = {
            "who": f"PID: {event.pid} (UID: {uid})",
            "what": f"'{cmd}' süreci başarısız oldu.",
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

        # Terminal Çıktısı (Sadece Medium ve üzeri riskler)
        if report["risk_score"] >= 40:
            mitre_tag = f" [MITRE: {report['mitre_technique']}]" if report['mitre_technique'] else ""
            print(f"\n[!] 5N1K TESPİTİ ({report['severity'].upper()}): {cmd} | Skor: {report['risk_score']}{mitre_tag} | Neden: {report['why']}")
  #          self.send_desktop_notification(f"ULAK: {cmd} İhlali", report['why'], report['severity'])

        # Dashboard'a veri gönderimi
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

        print("\n" + "="*60)
        print(" ULAK AI SENSÖRÜ AKTİF - RISK ENGINE (v3.0) DEVREDE")
        print("="*60 + "\n")

        self.b["events"].open_perf_buffer(self.print_event)
        while True:
            try:
                self.b.perf_buffer_poll()
            except KeyboardInterrupt:
                sys.exit(0)

if __name__ == "__main__":
    UlakHandler().run()