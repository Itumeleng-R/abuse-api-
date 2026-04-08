"""
models.py — Pydantic request and response schemas.
Mirrors the AbuseIPDB API response structure exactly so your
existing abuseipdb.py client works with zero changes.
"""

from pydantic import BaseModel, Field
from typing import Optional


class ReportRequest(BaseModel):
    ip: str                  = Field(..., description="IP address being reported")
    categories: str          = Field(..., description="Comma-separated category IDs")
    comment: Optional[str]   = Field(None, description="Description of the abuse")
    reporter_ip: Optional[str] = Field("127.0.0.1", description="IP of reporter")


class ReportResponse(BaseModel):
    data: dict


class CheckData(BaseModel):
    ipAddress:            str
    isPublic:             bool   = True
    ipVersion:            int    = 4
    isWhitelisted:        bool   = False
    abuseConfidenceScore: int
    countryCode:          str    = "ZZ"
    usageType:            str    = "Unknown"
    isp:                  str    = "Unknown ISP"
    domain:               str    = "unknown"
    isTor:                bool   = False
    totalReports:         int
    numDistinctUsers:     int
    lastReportedAt:       Optional[str] = None


class CheckResponse(BaseModel):
    data: CheckData