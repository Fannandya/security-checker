# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 Fannandya
# Part of OSC (Open Source Code Scanner) - https://github.com/Fannandya/security-checker

import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch

from osc.web.app import app
from osc.web.models import ScanStatus

client = TestClient(app)


def test_health_check():
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert "version" in data


def test_scan_api_endpoints():
    with patch('osc.web.manager.ScanManager.start_scan', return_value="testscan123"):
        # Post scan
        res = client.post("/api/scan", json={"target": "https://test.local"})
        assert res.status_code == 200
        assert res.json()["scan_id"] == "testscan123"

    # Get scan not found
    res = client.get("/api/scans/nonexistent")
    assert res.status_code == 404

    # Get logs not found
    res = client.get("/api/scans/nonexistent/logs")
    assert res.status_code == 404


def test_get_scan_detail_and_logs():
    from osc.web.app import manager

    dummy_status = ScanStatus(
        scan_id="abc12345",
        target="https://dummy.target",
        status="completed",
        created_at="2026-10-24 10:00:00",
        findings_count=3,
    )
    with manager._lock:
        manager._scans["abc12345"] = dummy_status
        manager._logs["abc12345"] = ["line 1", "line 2", "line 3"]

    # Detail
    res = client.get("/api/scans/abc12345")
    assert res.status_code == 200
    assert res.json()["scan_id"] == "abc12345"
    assert res.json()["findings_count"] == 3

    # Logs
    res = client.get("/api/scans/abc12345/logs?offset=1")
    assert res.status_code == 200
    assert res.json()["logs"] == ["line 2", "line 3"]

    # Scans list
    res = client.get("/api/scans")
    assert res.status_code == 200
    scan_ids = [s["scan_id"] for s in res.json()]
    assert "abc12345" in scan_ids


def test_index_dashboard_view():
    res = client.get("/")
    assert res.status_code == 200
    assert "OSC Web Scanner" in res.text
    assert "Launch Security Scan" in res.text


def test_report_download(tmp_path):
    from osc.web.app import manager

    dummy_report_html = tmp_path / "report.html"
    dummy_report_html.write_text("<html><body>Report</body></html>")

    dummy_status = ScanStatus(
        scan_id="report123",
        target="https://dummy.target",
        status="completed",
        created_at="2026-10-24 10:00:00",
        artifacts={"html": str(dummy_report_html)}
    )
    with manager._lock:
        manager._scans["report123"] = dummy_status

    res = client.get("/api/scans/report123/report/html")
    assert res.status_code == 200
    assert "Report" in res.text

    # Invalid format
    res = client.get("/api/scans/report123/report/invalid")
    assert res.status_code == 400

