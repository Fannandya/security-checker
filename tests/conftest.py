"""Shared pytest fixtures for the OSC test suite."""

import pytest

from osc.scanner import EnhancedOSCScanner


@pytest.fixture
def scanner():
    """A scanner instance that never touches the network on construction."""
    return EnhancedOSCScanner('https://example.test', max_threads=2, timeout=1, depth=0)


@pytest.fixture
def sample_finding():
    return {
        'url': 'https://example.test/leak.env',
        'category': 'api_keys',
        'value': 'sk_live_abcdefghijklmnop',
        'confidence': 'high',
        'pattern': 'sk_(?:live|test)_[A-Za-z0-9]{16,}',
        'content_type': 'text/plain',
        'context': 'API_KEY=sk_live_abcdefghijklmnop',
    }


@pytest.fixture
def sample_report(sample_finding):
    return {
        'scan_info': {
            'target': 'https://example.test',
            'session_provided': False,
            'aggressive': False,
            'scan_duration': 1.23,
            'urls_scanned': 3,
            'errors': 0,
            'depth': 0,
            'timestamp': '2026-08-12 00:00:00',
            'scanner_version': '2.3.0',
        },
        'summary': {
            'total_findings': 1,
            'category_counts': {'api_keys': 1},
            'findings_by_category': {'api_keys': [sample_finding]},
            'risk_assessment': 'HIGH',
        },
        'findings': [sample_finding],
    }
