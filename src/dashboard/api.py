from fastapi import FastAPI
import uvicorn

app = FastAPI(title="Ulak AI Dashboard")

# Raporların tutulacağı geçici bellek
reports = []

@app.get("/reports")
def get_reports():
    return reports

@app.post("/add_report")
def add_report(report: dict):
    reports.insert(0, report) # En son raporu başa ekle
    return {"status": "success"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)