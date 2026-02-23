import os, sys, json, re, subprocess, asyncio, uvicorn
from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles

# --- PATH & AI SETUP ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, "../../"))
sys.path.append(os.path.join(PROJECT_ROOT, "src"))

try:
    from analyzer.engine import NativeAIAnalyzer
    ai_engine = NativeAIAnalyzer(model="tinyllama")
except Exception as e:
    print(f"[Warn] AI Engine load failed: {e}")
    ai_engine = None

FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")
RULES_PATH = os.path.join(PROJECT_ROOT, "config/rules.json")

app = FastAPI(title="ULAK AI Backend")
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

# --- INTERACTIVE DESKTOP NOTIFICATION (ROOT BYPASS) ---
async def send_interactive_mascot_notification(incident):
    raw_data = incident.get("raw_data", {})
    cmd, pid = raw_data.get("cmd", "Unknown"), raw_data.get("pid", 0)
    why = incident.get("why", "Critical Breach")

    username, uid = "erogluyusuf", "1000"
    icon_path = os.path.join(FRONTEND_DIR, "assets", "mascot.png")
    icon_arg = f"-i {icon_path}" if os.path.exists(icon_path) else ""

    title = "ULAK"
    msg = f"Anomaly detected, Boss!\nProcess: {cmd} (PID: {pid})\nReason: {why}"

    # KRİTİK DÜZELTME: '-w' eklendi! Python artık butona basılmasını bekleyecek.
    bash_cmd = f"sudo -u {username} DISPLAY=:0 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{uid}/bus notify-send -w -u critical {icon_arg} -t 0 -A 'fix=Remediate' -A 'ignore=Dismiss' '{title}' '{msg}'"

    try:
        print(f"[ULAK-NOTIFY] Alert sent to desktop. Waiting for user input...")
        proc = await asyncio.create_subprocess_shell(bash_cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        stdout, _ = await proc.communicate()
        action = stdout.decode().strip()

        print(f"[ULAK-NOTIFY] User clicked: '{action}'")

        if action == "fix" and pid != 0:
            print(f"\n[ULAK-MASCOT] Execution approved! Killing PID {pid}\n")
            subprocess.run(f"kill -9 {pid}", shell=True)

            success_msg = f"Threat ({cmd}) successfully neutralized!"
            success_cmd = f"sudo -u {username} DISPLAY=:0 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{uid}/bus notify-send -u normal {icon_arg} '✅ OPERATION COMPLETE' '{success_msg}'"
            subprocess.run(success_cmd, shell=True)
        elif action == "ignore":
            print(f"[ULAK-MASCOT] User dismissed the alert for PID {pid}.")

    except Exception as e:
        print(f"[!] Mascot notification error: {e}")

# --- API ENDPOINTS ---
@app.post("/report")
async def receive_report(request: Request):
    try:
        report = await request.json()
        incidents.insert(0, report)
        if len(incidents) > 100: incidents.pop()

        # Skoru 70 ve üzeri olanlarda interaktif bildirim fırlat
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

@app.post("/execute_fix")
async def execute_fix(request: Request):
    try:
        command = (await request.json()).get("command", "")
        if not command or "No valid command" in command:
            return {"status": "failed", "error": "No valid command to execute."}

        print(f"\n[ULAK-EXEC] Intervention started: {command}\n")
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=15)

        return {"status": "success", "output": result.stdout} if result.returncode == 0 else {"status": "failed", "output": result.stdout, "error": result.stderr}

    except subprocess.TimeoutExpired: return {"status": "failed", "error": "Command timed out (>15s)."}
    except Exception as e: return {"status": "failed", "error": str(e)}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)