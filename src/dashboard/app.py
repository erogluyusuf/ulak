import os, sys, json, re, subprocess, asyncio, uvicorn
from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, "../../"))
sys.path.append(os.path.join(PROJECT_ROOT, "src"))

try:
    from analyzer.engine import NativeAIAnalyzer
    ai_engine = NativeAIAnalyzer(model="tinyllama")
except Exception as e:
    print(f"[WARNING] Heuristic Engine load failed: {e}")
    ai_engine = None

FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")
RULES_PATH = os.path.join(PROJECT_ROOT, "config/rules.json")

app = FastAPI(title="ULAK EDR Security Center")
app.mount("/assets", StaticFiles(directory=os.path.join(FRONTEND_DIR, "assets")), name="assets")

incidents = []

def load_rules():
    try:
        if os.path.exists(RULES_PATH):
            with open(RULES_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception as e:
        print(f"[!] Rules load error: {e}")
    return {}

async def send_interactive_mascot_notification(incident):

    import pwd
    import os

    raw_data = incident.get("raw_data", {})
    cmd = raw_data.get("cmd", "Unknown")
    pid = raw_data.get("pid", 0)
    why = incident.get("why", "Critical Breach")

    try:

        event_uid = int(raw_data.get("uid", 1000))
        user_info = pwd.getpwuid(event_uid)
        username = user_info.pw_name
        uid = str(event_uid)
    except Exception as e:

        username = os.environ.get("USER") or os.environ.get("LOGNAME") or "root"
        try:
            uid = str(pwd.getpwnam(username).pw_uid)
        except:
            uid = "1000"

    icon_path = os.path.join(FRONTEND_DIR, "assets", "mascot.png")
    icon_arg = f"-i {icon_path}" if os.path.exists(icon_path) else ""

    title = "ULAK EDR - SECURITY ALERT"
    msg = (
        f"Anomaly detected, Boss!\n"
        f"Process: {cmd} (PID: {pid})\n"
        f"User: {username}\n"
        f"Reason: {why}"
    )

    bash_cmd = (
        f"sudo -u {username} DISPLAY=:0 "
        f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{uid}/bus "
        f"notify-send -w -u critical {icon_arg} -t 0 "
        f"-A 'fix=Remediate' -A 'ignore=Dismiss' '{title}' '{msg}'"
    )

    try:
        print(f"[ULAK-NOTIFY] Alert dispatched to user '{username}'. Waiting for response...")

        proc = await asyncio.create_subprocess_shell(
            bash_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        action = stdout.decode().strip()

        print(f"[ULAK-NOTIFY] Action received from '{username}': '{action}'")

        if action == "fix" and pid != 0:
            print(f"\n[ULAK-MASCOT] Remediation approved! Terminating PID {pid}\n")

            subprocess.run(f"kill -9 {pid}", shell=True)

            success_msg = f"Threat neutralized: {cmd} has been terminated by {username}."
            success_cmd = (
                f"sudo -u {username} DISPLAY=:0 "
                f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{uid}/bus "
                f"notify-send -u normal {icon_arg} 'INCIDENT RESOLVED' '{success_msg}'"
            )
            subprocess.run(success_cmd, shell=True)

        elif action == "ignore":
            print(f"[ULAK-MASCOT] Incident dismissed for PID {pid} by user decision.")

    except Exception as e:
        print(f"[!] Notification Framework Error: {e}")

@app.post("/report")
async def receive_report(request: Request):
    try:
        report = await request.json()
        incidents.insert(0, report)
        if len(incidents) > 100: incidents.pop()

        if report.get("risk_score", 0) >= 70:
            asyncio.create_task(send_interactive_mascot_notification(report))
        return {"status": "ok"}
    except:
        return {"status": "error"}

@app.get("/data")
async def get_data():
    return incidents

@app.get("/", response_class=HTMLResponse)
async def get_dashboard():
    return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))

@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    fav_path = os.path.join(FRONTEND_DIR, "assets/favicon.ico")
    return FileResponse(fav_path) if os.path.exists(fav_path) else Response(status_code=204)

@app.post("/fix")
async def generate_fix_command(request: Request):
    try:
        body = await request.body()
        if not body: return {"status": "error", "command": "echo 'Error: Empty payload.'"}

        incident = json.loads(body)
        raw_data = incident.get("raw_data", {})
        cmd, pid = raw_data.get("cmd", "unknown"), raw_data.get("pid", 0)
        why, source = incident.get("why", "Unknown Error"), raw_data.get("source") or incident.get("source", "")

        suggested_cmd, rules = "", load_rules()

        if "Rules" in source or "Local" in source:
            match = re.search(r"\((.*?)\)", source)
            if match and (rule_data := rules.get("service_patterns", {}).get(match.group(1))):
                suggested_cmd = rule_data.get("action_cmd", "")

        if suggested_cmd and "{pid}" in suggested_cmd:
            suggested_cmd = suggested_cmd.replace("{pid}", str(pid))

        if not suggested_cmd:
            suggested_cmd = f"# AI Suggestion\n# Error: {why}\nsudo systemctl restart {cmd} || kill -9 {pid}" if ai_engine else f"kill -9 {pid}"

        return {"status": "ready_for_approval", "command": suggested_cmd, "message": "Fix command ready."}
    except Exception as e:
        print(f"[!] /fix Error: {e}")
        return {"status": "error", "command": "echo 'Failed to generate fix.'"}

CRITICAL_WHITELIST = [
    "systemd", "init", "dbus-daemon", "Xorg", "gnome-shell", "kthreadd",
    "handler.py", "main.py", "ollama", "docker-proxy", "containerd",
    "sshd", "bash", "sudo"
]

@app.post("/execute_fix")
async def execute_fix(request: Request):
    try:
        data = await request.json()
        command = data.get("command", "")

        if not command or "No valid command" in command:
            return {"status": "failed", "error": "Geçerli bir komut yok."}

        for safe_proc in CRITICAL_WHITELIST:
            if safe_proc in command:
                print(f"[ULAK-PROTECT] CRITICAL PROCESS PROTECTION: {safe_proc} cannot be terminated!")
                return {
                    "status": "failed",
                    "error": f"SECURITY VIOLATION: {safe_proc} is a system-critical process and cannot be stopped by ULAK."
                }

        if "kill" in command:

            pid_match = re.search(r"kill\s+-9\s+(\d+)", command)
            if pid_match:
                target_pid = int(pid_match.group(1))
                if target_pid <= 100:
                    return {"status": "failed", "error": "Düşük seviyeli sistem PID'leri (PID <= 100) korunmaktadır."}

        print(f"\n[ULAK-EXEC] Mitigation triggered: {command}\n")
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=15
)

        return {"status": "success", "output": result.stdout} if result.returncode == 0 else {"status": "failed", "output": result.stdout, "error": result.stderr}

    except Exception as e:
        return {"status": "failed", "error": str(e)}
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
