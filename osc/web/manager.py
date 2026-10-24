# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 Fannandya
# Part of OSC (Open Source Code Scanner) - https://github.com/Fannandya/security-checker

"""Scan manager for executing and tracking OSC scans in the background."""

import os
import sys
import time
import uuid
import threading
from typing import Dict, List, Optional

from osc.scanner import EnhancedOSCScanner
from osc.cli import parse_ports
from osc import reporting
from osc.web.models import ScanRequest, ScanStatus


import re

_ANSI_ESCAPE = re.compile(r'\x1b\[[0-9;]*[a-zA-Z]')


class _LogCaptureStream:
    """Stream wrapper that captures written lines into an in-memory buffer while optionally forwarding."""

    def __init__(self, target_list: List[str], forward_stream=None):
        self.target_list = target_list
        self.forward_stream = forward_stream
        self._current_line = []

    def write(self, text: str):
        if self.forward_stream:
            try:
                self.forward_stream.write(text)
                self.forward_stream.flush()
            except Exception:
                pass

        for char in text:
            if char == '\n':
                raw_line = "".join(self._current_line).rstrip('\r')
                clean_line = _ANSI_ESCAPE.sub('', raw_line)
                self.target_list.append(clean_line)
                self._current_line = []
            else:
                self._current_line.append(char)

    def flush(self):
        if self.forward_stream:
            try:
                self.forward_stream.flush()
            except Exception:
                pass


class ScanManager:
    """Manages background OSC scan executions, progress tracking, and report retention."""

    def __init__(self, output_dir: str = "output"):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)
        self._scans: Dict[str, ScanStatus] = {}
        self._logs: Dict[str, List[str]] = {}
        self._lock = threading.Lock()

    def start_scan(self, req: ScanRequest) -> str:
        scan_id = uuid.uuid4().hex[:12]
        now = time.strftime('%Y-%m-%d %H:%M:%S')

        status = ScanStatus(
            scan_id=scan_id,
            target=req.target,
            status="queued",
            created_at=now,
        )

        with self._lock:
            self._scans[scan_id] = status
            self._logs[scan_id] = [f"[{now}] Scan {scan_id} queued for {req.target}"]

        worker = threading.Thread(
            target=self._run_scan_worker,
            args=(scan_id, req),
            name=f"osc-scan-{scan_id}",
            daemon=True,
        )
        worker.start()
        return scan_id

    def _run_scan_worker(self, scan_id: str, req: ScanRequest):
        started_time = time.time()
        started_str = time.strftime('%Y-%m-%d %H:%M:%S')

        with self._lock:
            if scan_id in self._scans:
                self._scans[scan_id].status = "running"
                self._scans[scan_id].started_at = started_str

        log_buffer = self._logs.get(scan_id, [])
        log_stream = _LogCaptureStream(log_buffer, forward_stream=sys.stdout)

        orig_stdout = sys.stdout
        orig_stderr = sys.stderr

        try:
            sys.stdout = log_stream
            sys.stderr = log_stream

            ports = parse_ports(req.ports) if req.ports else None
            active_checks = [c.strip() for c in req.active_checks.split(',') if c.strip()] if req.active_checks else None

            scanner = EnhancedOSCScanner(
                target=req.target,
                session_cookie=req.session_cookie,
                max_threads=req.max_threads,
                timeout=req.timeout,
                depth=req.depth,
                max_urls=req.max_urls,
                delay=req.delay,
                retries=req.retries,
                verify=req.verify,
                verbose=True,
                aggressive=req.aggressive,
                skip_audit=req.skip_audit,
                recon=req.recon,
                ports=ports,
                active=req.active,
                active_checks=active_checks,
            )

            json_path = os.path.join(self.output_dir, f"scan_{scan_id}.json")
            html_path = os.path.join(self.output_dir, f"scan_{scan_id}.html")
            csv_path = os.path.join(self.output_dir, f"scan_{scan_id}.csv")

            scanner.run_scan(output_file=json_path, html_file=html_path, csv_file=csv_path)

            report = scanner.generate_report()
            if not os.path.exists(html_path):
                reporting.write_html(report, html_path)
            if not os.path.exists(csv_path):
                reporting.write_csv(report, csv_path)

            summary = report.get('summary', {})
            duration = round(time.time() - started_time, 2)
            finished_str = time.strftime('%Y-%m-%d %H:%M:%S')

            with self._lock:
                if scan_id in self._scans:
                    sc = self._scans[scan_id]
                    sc.status = "completed"
                    sc.finished_at = finished_str
                    sc.duration = duration
                    sc.urls_scanned = len(scanner.visited_urls)
                    sc.findings_count = summary.get('total_findings', len(scanner.found_sensitive_data))
                    sc.risk_assessment = summary.get('risk_assessment', 'NONE')
                    sc.category_counts = summary.get('category_counts', {})
                    sc.artifacts = {
                        "json": json_path,
                        "html": html_path,
                        "csv": csv_path,
                    }
                    sc.summary = summary

        except Exception as exc:
            duration = round(time.time() - started_time, 2)
            finished_str = time.strftime('%Y-%m-%d %H:%M:%S')
            log_buffer.append(f"[-] Scan encountered an error: {exc}")
            with self._lock:
                if scan_id in self._scans:
                    sc = self._scans[scan_id]
                    sc.status = "failed"
                    sc.finished_at = finished_str
                    sc.duration = duration
                    sc.error_message = str(exc)

        finally:
            sys.stdout = orig_stdout
            sys.stderr = orig_stderr

    def get_scan(self, scan_id: str) -> Optional[ScanStatus]:
        with self._lock:
            return self._scans.get(scan_id)

    def get_logs(self, scan_id: str, offset: int = 0) -> List[str]:
        with self._lock:
            lines = self._logs.get(scan_id, [])
            if offset >= len(lines):
                return []
            return list(lines[offset:])

    def list_scans(self) -> List[ScanStatus]:
        with self._lock:
            return sorted(self._scans.values(), key=lambda s: s.created_at, reverse=True)

    def get_report_file(self, scan_id: str, fmt: str) -> Optional[str]:
        scan = self.get_scan(scan_id)
        if not scan or not scan.artifacts:
            path = os.path.join(self.output_dir, f"scan_{scan_id}.{fmt}")
            if os.path.exists(path):
                return path
            return None
        return scan.artifacts.get(fmt)
