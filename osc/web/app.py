# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 Fannandya
# Part of OSC (Open Source Code Scanner) - https://github.com/Fannandya/security-checker

"""FastAPI web server for OSC - Open Source Code Scanner."""

import os
from typing import List, Optional
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles

from osc.scanner import __version__
from osc.web.models import ScanRequest, ScanStatus
from osc.web.manager import ScanManager

app = FastAPI(
    title="OSC Web Scanner",
    description="Web UI and REST API for OSC (Open Source Code Scanner)",
    version=__version__,
)

output_dir = os.environ.get("OSC_OUTPUT_DIR", "output")
manager = ScanManager(output_dir=output_dir)

current_dir = os.path.dirname(os.path.abspath(__file__))
templates_dir = os.path.join(current_dir, "templates")
static_dir = os.path.join(current_dir, "static")

if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")


@app.get("/api/health")
def health_check():
    """Healthcheck endpoint for Traefik, Docker, and Proxmox."""
    return {
        "status": "ok",
        "version": __version__,
        "scanner": "EnhancedOSCScanner",
    }


@app.post("/api/scan")
def trigger_scan(req: ScanRequest):
    """Trigger a new background OSC security scan."""
    scan_id = manager.start_scan(req)
    return {"scan_id": scan_id, "status": "queued", "target": req.target}


@app.get("/api/scans", response_model=List[ScanStatus])
def list_scans():
    """List all registered scans."""
    return manager.list_scans()


@app.get("/api/scans/{scan_id}", response_model=ScanStatus)
def get_scan(scan_id: str):
    """Get current status and summary for a scan."""
    scan = manager.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@app.get("/api/scans/{scan_id}/logs")
def get_scan_logs(scan_id: str, offset: int = Query(0, ge=0)):
    """Retrieve scan execution logs from a given offset."""
    scan = manager.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    logs = manager.get_logs(scan_id, offset=offset)
    return {"scan_id": scan_id, "offset": offset, "logs": logs}


@app.get("/api/scans/{scan_id}/report/{fmt}")
def get_report(scan_id: str, fmt: str):
    """Retrieve or download a generated report (html, json, or csv)."""
    fmt = fmt.lower()
    if fmt not in ("html", "json", "csv"):
        raise HTTPException(status_code=400, detail="Invalid format. Supported: html, json, csv")

    file_path = manager.get_report_file(scan_id, fmt)
    if not file_path or not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail=f"{fmt.upper()} report not found or not yet generated")

    media_types = {
        "html": "text/html",
        "json": "application/json",
        "csv": "text/csv",
    }
    # For HTML we display in browser; for JSON/CSV we offer download filename
    filename = f"scan_{scan_id}.{fmt}" if fmt in ("json", "csv") else None
    return FileResponse(file_path, media_type=media_types[fmt], filename=filename)


@app.get("/", response_class=HTMLResponse)
def index_view():
    """Serve the single page application dashboard."""
    index_file = os.path.join(templates_dir, "index.html")
    if os.path.exists(index_file):
        with open(index_file, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>OSC Web Scanner</h1><p>Dashboard template not yet installed. Visit /api/health</p>"
