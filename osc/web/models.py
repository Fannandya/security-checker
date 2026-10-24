# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 Fannandya
# Part of OSC (Open Source Code Scanner) - https://github.com/Fannandya/security-checker

"""Pydantic models for OSC Web."""

from typing import Optional, Dict, Any
from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    target: str = Field(..., description="Target URL to scan (e.g. https://example.com)")
    session_cookie: Optional[str] = Field(None, description="Session cookie for authenticated scanning")
    max_threads: int = Field(10, ge=1, le=50, description="Worker threads")
    timeout: int = Field(10, ge=1, le=60, description="Request timeout in seconds")
    depth: int = Field(1, ge=0, le=5, description="Crawl depth (0=seeds only)")
    max_urls: int = Field(1000, ge=1, le=50000, description="Max URLs budget")
    delay: float = Field(0.0, ge=0.0, le=10.0, description="Delay between requests in seconds")
    retries: int = Field(2, ge=0, le=5, description="HTTP retries")
    verify: bool = Field(False, description="Enable TLS certificate verification")
    skip_audit: bool = Field(False, description="Skip security posture audit")
    recon: bool = Field(True, description="Enable recon mode (DNS, ports, WAF, fingerprint)")
    aggressive: bool = Field(True, description="Enable aggressive endpoint brute-force")
    active: bool = Field(False, description="Enable active vulnerability probing")
    active_checks: Optional[str] = Field(None, description="Comma-separated active checks (e.g. xss,sqli)")
    ports: Optional[str] = Field(None, description="Comma-separated ports to scan (e.g. 80,443,8080)")


class ScanStatus(BaseModel):
    scan_id: str
    target: str
    status: str = "queued"  # queued, running, completed, failed
    created_at: str
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    duration: Optional[float] = None
    urls_scanned: int = 0
    findings_count: int = 0
    risk_assessment: Optional[str] = None
    category_counts: Dict[str, int] = Field(default_factory=dict)
    error_message: Optional[str] = None
    artifacts: Dict[str, str] = Field(default_factory=dict)
    summary: Optional[Dict[str, Any]] = None
