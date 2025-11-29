#!/usr/bin/env python3
"""
Sentinel Alert Enrichment Pipeline
Purpose: Reduce alert triage time from 10 minutes to 30 seconds
Author: Madhur Hase
Version: 1.1

This script enriches Sentinel alerts with threat intelligence:
- AbuseIPDB IP reputation checks
- VirusTotal file hash lookups
- (Planned) Geolocation data
- (Planned) Internal blocklist correlation
- Risk-based auto-ticketing to Tier 3
"""

import requests
import json
import os
from datetime import datetime, timezone
from typing import Dict, Any, Optional


class AlertEnricher:
    """Enriches Sentinel alerts with threat intelligence."""
    
    def __init__(self, abuseipdb_key: str, virustotal_key: str):
        """Initialize enricher with API keys."""
        if not abuseipdb_key or abuseipdb_key.startswith("YOUR_"):
            raise ValueError("Invalid or missing AbuseIPDB API key")
        if not virustotal_key or virustotal_key.startswith("YOUR_"):
            raise ValueError("Invalid or missing VirusTotal API key")

        self.abuseipdb_api = abuseipdb_key
        self.virustotal_api = virustotal_key
        self.session = requests.Session()
    
    def check_ip_reputation(self, ip_address: str) -> Dict[str, Any]:
        """
        Check IP reputation on AbuseIPDB.
        Returns:
            On success:
                {
                    'source': 'AbuseIPDB',
                    'ip': str,
                    'abuse_score': 0-100,
                    'reports': int,
                    'status': 'malicious' | 'clean'
                }
            On error:
                {
                    'source': 'AbuseIPDB',
                    'ip': str,
                    'error': str,
                    'status': 'unknown'
                }
        """
        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {"Key": self.abuseipdb_api, "Accept": "application/json"}
            params = {"ipAddress": ip_address, "maxAgeInDays": 90}
            
            response = self.session.get(url, headers=headers, params=params, timeout=5)
            response.raise_for_status()
            
            data = response.json()
            abuse_score = data.get("data", {}).get("abuseConfidenceScore", 0)
            reports = data.get("data", {}).get("totalReports", 0)
            
            return {
                "source": "AbuseIPDB",
                "ip": ip_address,
                "abuse_score": abuse_score,
                "reports": reports,
                "status": "malicious" if abuse_score > 50 else "clean"
            }
        except Exception as e:
            return {"source": "AbuseIPDB", "ip": ip_address, "error": str(e), "status": "unknown"}
    
    def check_file_hash(self, file_hash: str) -> Dict[str, Any]:
        """
        Check file hash on VirusTotal.
        Returns:
            On success:
                {
                    'source': 'VirusTotal',
                    'hash': str,
                    'malicious_detections': int,
                    'status': 'malicious' | 'clean'
                }
            On error:
                {
                    'source': 'VirusTotal',
                    'hash': str,
                    'error': str,
                    'status': 'unknown'
                }
        """
        try:
            url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
            headers = {"x-apikey": self.virustotal_api}
            
            response = self.session.get(url, headers=headers, timeout=5)
            response.raise_for_status()
            
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            
            return {
                "source": "VirusTotal",
                "hash": file_hash,
                "malicious_detections": malicious,
                "status": "malicious" if malicious > 5 else "clean"
            }
        except Exception as e:
            return {"source": "VirusTotal", "hash": file_hash, "error": str(e), "status": "unknown"}
    
    def calculate_risk_score(self, ip_score: float, file_score: float) -> float:
        """
        Calculate combined risk score with weighted logic.
        Weights: IP reputation 50%, File reputation 50%
        Returns: 0.0 to 1.0
        """
        normalized_ip = min(ip_score / 100, 1.0)   # AbuseIPDB is 0-100
        normalized_file = min(file_score / 70, 1.0)  # VirusTotal has ~70 engines
        
        risk = (normalized_ip * 0.5) + (normalized_file * 0.5)
        return round(risk, 2)
    
    def enrich_alert(self, source_ip: str, file_hash: Optional[str] = None) -> Dict[str, Any]:
        """
        Main enrichment function. Checks threat intel and makes risk-based decision.
        
        Args:
            source_ip: Source IP address to check
            file_hash: Optional file hash to check
        
        Returns: Enriched alert data with risk score and recommended action
        """
        print(f"[ENRICHING] IP: {source_ip} | Hash: {file_hash}")
        
        # Check IP reputation
        ip_rep = self.check_ip_reputation(source_ip)
        ip_error = ip_rep.get("status") == "unknown"
        ip_score = ip_rep.get("abuse_score", 0) if not ip_error else 0
        
        # Check file hash if provided
        file_rep: Dict[str, Any] = {}
        file_error = False
        file_score = 0
        if file_hash:
            file_rep = self.check_file_hash(file_hash)
            file_error = file_rep.get("status") == "unknown"
            file_score = file_rep.get("malicious_detections", 0) if not file_error else 0
        
        # Calculate risk score if we have at least some intel
        if ip_error and (file_error or not file_hash):
            risk_score = None
        else:
            risk_score = self.calculate_risk_score(ip_score, file_score)
        
        # Risk-based decision
        if risk_score is None:
            action = "MANUAL_REVIEW"
            priority = "MEDIUM"
            severity = "Unknown"
        elif risk_score > 0.7:
            action = "AUTO_TICKET_TIER3"
            priority = "HIGH"
            severity = "Critical"
        elif risk_score > 0.4:
            action = "MANUAL_REVIEW"
            priority = "MEDIUM"
            severity = "High"
        else:
            action = "CLOSE_FP"
            priority = "LOW"
            severity = "Low"
        
        # Build enrichment result
        result = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": source_ip,
            "file_hash": file_hash,
            "risk_score": risk_score,
            "severity": severity,
            "action": action,
            "priority": priority,
            "ip_reputation": ip_rep,
            "file_reputation": file_rep,
            "recommendation": f"Risk score {risk_score}: {action}" if risk_score is not None else "Insufficient intel: manual review required"
        }
        
        print(json.dumps(result, indent=2))
        return result


def main():
    """Example usage."""
    abuseipdb_key = os.getenv("ABUSEIPDB_API_KEY")
    virustotal_key = os.getenv("VIRUSTOTAL_API_KEY")
    
    enricher = AlertEnricher(abuseipdb_key, virustotal_key)
    
    result = enricher.enrich_alert(
        source_ip="192.168.1.100",
        file_hash="a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"
    )
    
    print("\n[OUTPUT] Ready for SOAR integration:")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
