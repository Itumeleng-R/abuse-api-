"""
routes.py — API endpoint definitions.
Two endpoints mirror the real AbuseIPDB API:
  GET  /api/v2/check   — check an IP's abuse history
  POST /api/v2/report  — submit a new abuse report
"""

from fastapi import APIRouter, Query, Header, HTTPException, Depends
from typing import Optional
import os

from .database import (
    get_reports, insert_report, get_metadata,
    upsert_metadata, compute_confidence
)
from .models import CheckResponse, CheckData, ReportRequest, ReportResponse

router = APIRouter(prefix="/api/v2")

API_KEY = os.getenv("LOCAL_API_KEY", "test-key-123")


def verify_key(key: Optional[str] = Header(None, alias="Key")):
    """
    Simple API key auth — mirrors AbuseIPDB's header-based auth.
    Set LOCAL_API_KEY env var or use the default 'test-key-123'.
    """
    if key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return key


@router.get("/check", response_model=CheckResponse)
def check_ip(
    ipAddress:    str = Query(..., description="IP address to check"),
    maxAgeInDays: int = Query(90,  description="Report window in days"),
    _key = Depends(verify_key),
):
    """
    Check an IP address against the local abuse database.
    Response format mirrors AbuseIPDB v2 exactly.
    """
    reports  = get_reports(ipAddress, maxAgeInDays)
    meta     = get_metadata(ipAddress) or {}
    score    = compute_confidence(reports)
    distinct = len(set(r["reporter_ip"] for r in reports))
    last_seen = reports[0]["reported_at"] if reports else None

    return CheckResponse(data=CheckData(
        ipAddress            = ipAddress,
        isWhitelisted        = bool(meta.get("is_whitelisted", False)),
        abuseConfidenceScore = score,
        countryCode          = meta.get("country_code", "ZZ"),
        usageType            = meta.get("usage_type", "Unknown"),
        isp                  = meta.get("isp", "Unknown ISP"),
        domain               = meta.get("domain", "unknown"),
        isTor                = bool(meta.get("is_tor", False)),
        totalReports         = len(reports),
        numDistinctUsers     = distinct,
        lastReportedAt       = last_seen,
    ))


@router.post("/report", response_model=ReportResponse)
def report_ip(
    body: ReportRequest,
    _key = Depends(verify_key),
):
    """
    Submit an abuse report for an IP address.
    Category IDs follow AbuseIPDB's category list (e.g. 18 = Brute Force).
    """
    # Take the first category from the comma-separated list
    try:
        category = int(body.categories.split(",")[0].strip())
    except ValueError:
        raise HTTPException(status_code=422, detail="Invalid category format")

    insert_report(
        ip          = body.ip,
        category    = category,
        comment     = body.comment or "",
        reporter_ip = body.reporter_ip or "127.0.0.1",
    )

    return ReportResponse(data={
        "ipAddress": body.ip,
        "abuseConfidenceScore": compute_confidence(get_reports(body.ip)),
    })