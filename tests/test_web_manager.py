# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 Fannandya
# Part of OSC (Open Source Code Scanner) - https://github.com/Fannandya/security-checker

import time
import os
import pytest
from unittest.mock import patch, MagicMock

from osc.web.models import ScanRequest, ScanStatus
from osc.web.manager import ScanManager


def test_scan_request_defaults():
    req = ScanRequest(target="https://example.com")
    assert req.target == "https://example.com"
    assert req.max_threads == 10
    assert req.recon is True
    assert req.active is False
    assert req.verify is False


def test_scan_manager_lifecycle(tmp_path):
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    manager = ScanManager(output_dir=str(output_dir))

    req = ScanRequest(target="https://example.com", max_urls=5)
    
    # Mock scanner run_scan to avoid actual network traffic during unit test
    def mock_run_scan(self, output_file=None, html_file=None, csv_file=None):
        self.found_sensitive_data = [
            {'category': 'api_keys', 'url': 'https://example.com/api', 'value': 'secret123'}
        ]
        self.visited_urls = {'https://example.com'}
        self.errors = 0
        self.start_time = time.time()
        # write report
        self.generate_report(output_file)
        if html_file:
            from osc import reporting
            rep = self.generate_report()
            reporting.write_html(rep, html_file)
        if csv_file:
            from osc import reporting
            rep = self.generate_report()
            reporting.write_csv(rep, csv_file)

    with patch('osc.scanner.EnhancedOSCScanner.run_scan', side_effect=mock_run_scan, autospec=True):
        scan_id = manager.start_scan(req)
        assert scan_id is not None
        
        # Wait for thread to finish
        for _ in range(50):
            status = manager.get_scan(scan_id)
            if status and status.status in ('completed', 'failed'):
                break
            time.sleep(0.05)
        
        status = manager.get_scan(scan_id)
        assert status is not None
        assert status.status == 'completed'
        assert status.findings_count == 1
        assert 'api_keys' in status.category_counts
        assert len(manager.list_scans()) >= 1

        logs = manager.get_logs(scan_id)
        assert isinstance(logs, list)
