import os
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles

app = FastAPI(title="ULAK AI Backend")

BASE_DIR = os.path.dirname(__file__)
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")

# ✅ STATIC MOUNT
app.mount(
    "/assets",
    StaticFiles(directory=os.path.join(FRONTEND_DIR, "assets")),
    name="assets"
)

incidents = []

@app.post("/report")
async def receive_report(request: Request):
    report = await request.json()
    incidents.insert(0, report)
    return {"status": "ok"}

@app.get("/data")
async def get_data():
    return incidents

@app.get("/", response_class=HTMLResponse)
async def get_dashboard():
    return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)