from typing import Dict, List, Optional
import requests
from dataclasses import dataclass
from enum import Enum

class HeaderStatus(Enum):
    PRESENT = "present"
    MISSING = "missing"
    MISCONFIGURED = "misconfigured"

@dataclass
class HeaderResult:
    name: str
    status: HeaderStatus
    value: Optional[str] = None
    recommendation: Optional[str] = None

def analyze_security_headers(url: str) -> List[HeaderResult]:
    """
    Analyze security headers for a given URL.
    
    Args:
        url: The URL to analyze
        
    Returns:
        List of HeaderResult objects containing analysis results
    """
    try:
        # Send request with timeout and verify SSL
        response = requests.get(url, timeout=10, verify=True)
    except requests.exceptions.RequestException as e:
        return [HeaderResult(
            name="Connection Error",
            status=HeaderStatus.MISSING,
            recommendation=f"Could not connect to URL: {str(e)}"
        )]

    headers = response.headers
    results: List[HeaderResult] = []

    # Define security headers to check with recommended values
    security_headers = {
        'Strict-Transport-Security': {
            'recommended': 'max-age=31536000; includeSubDomains',
            'required': ['max-age']
        },
        'X-Frame-Options': {
            'recommended': 'DENY',
            'required': ['DENY', 'SAMEORIGIN']
        },
        'X-Content-Type-Options': {
            'recommended': 'nosniff',
            'required': ['nosniff']
        },
        'Content-Security-Policy': {
            'recommended': "default-src 'self'",
            'required': ['default-src']
        },
        'X-XSS-Protection': {
            'recommended': '1; mode=block',
            'required': ['1']
        },
        'Referrer-Policy': {
            'recommended': 'strict-origin-when-cross-origin',
            'required': ['strict-origin-when-cross-origin', 'no-referrer']
        }
    }

    for header, config in security_headers.items():
        if header not in headers:
            results.append(HeaderResult(
                name=header,
                status=HeaderStatus.MISSING,
                recommendation=f"Add header with recommended value: {config['recommended']}"
            ))
            continue

        value = headers[header]
        
        # Check if header value contains required components
        has_required = any(req in value for req in config['required'])
        
        if not has_required:
            results.append(HeaderResult(
                name=header,
                status=HeaderStatus.MISCONFIGURED,
                value=value,
                recommendation=f"Current value may be insufficient. Recommended: {config['recommended']}"
            ))
        else:
            results.append(HeaderResult(
                name=header,
                status=HeaderStatus.PRESENT,
                value=value
            ))

    return results

def format_scan_results(results: List[HeaderResult]) -> Dict:
    """
    Format scan results into a structured dictionary.
    
    Args:
        results: List of HeaderResult objects
        
    Returns:
        Dictionary containing categorized results
    """
    return {
        "summary": {
            "total": len(results),
            "present": len([r for r in results if r.status == HeaderStatus.PRESENT]),
            "missing": len([r for r in results if r.status == HeaderStatus.MISSING]),
            "misconfigured": len([r for r in results if r.status == HeaderStatus.MISCONFIGURED])
        },
        "details": {
            "present": [r.__dict__ for r in results if r.status == HeaderStatus.PRESENT],
            "missing": [r.__dict__ for r in results if r.status == HeaderStatus.MISSING],
            "misconfigured": [r.__dict__ for r in results if r.status == HeaderStatus.MISCONFIGURED]
        }
    }
