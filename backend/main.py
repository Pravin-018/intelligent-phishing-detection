import csv
import io

from fastapi import FastAPI, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from backend.database import (
    delete_scan,
    get_all_scans,
    get_dashboard_metrics,
    get_scan_by_id,
    init_db,
    save_scan,
)
from backend.detection_engine import analyze_email, analyze_url

app = FastAPI(title="Intelligent Phishing Detection Platform")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class EmailRequest(BaseModel):
    subject: str = Field(default="")
    sender_email: str = Field(default="")
    display_name: str = Field(default="")
    reply_to: str = Field(default="")
    message: str = Field(default="")
    manual_url: str = Field(default="")
    attachment_hint: str = Field(default="")


class UrlRequest(BaseModel):
    url: str = Field(default="")


@app.on_event("startup")
def startup_event():
    init_db()


@app.get("/api/health")
def health_check():
    return {"status": "ok", "service": "phishing-detection"}


@app.get("/api/dashboard")
def dashboard():
    metrics = get_dashboard_metrics()
    return {"demo_data": True, "metrics": metrics}


@app.post("/api/analyze/email")
def analyze_email_route(payload: EmailRequest):
    result = analyze_email(payload.model_dump())
    save_scan(result)
    return result


@app.post("/api/analyze/url")
def analyze_url_route(payload: UrlRequest):
    result = analyze_url(payload.url)
    save_scan(result)
    return result


@app.get("/api/reports")
def get_reports():
    return {"scans": get_all_scans()}


@app.get("/api/reports/{scan_id}")
def get_report(scan_id: int):
    scan = get_scan_by_id(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"scan": scan}


@app.delete("/api/reports/{scan_id}")
def delete_report(scan_id: int):
    scan = get_scan_by_id(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    delete_scan(scan_id)
    return {"success": True, "deleted_id": scan_id}


@app.get("/api/reports/export")
def export_reports(format: str = "json"):
    scans = get_all_scans()
    if format == "json":
        return {"scans": scans}
    if format == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["id", "created_at", "analysis_type", "risk_score", "risk_level", "submitted_summary"])
        for scan in scans:
            writer.writerow([
                scan["id"],
                scan["created_at"],
                scan["analysis_type"],
                scan["risk_score"],
                scan["risk_level"],
                scan["submitted_summary"],
            ])
        response = Response(content=output.getvalue(), media_type="text/csv")
        response.headers["Content-Disposition"] = "attachment; filename=scans-summary.csv"
        return response
    raise HTTPException(status_code=400, detail="Unsupported export format")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=False)
