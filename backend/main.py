from fastapi import FastAPI, HTTPException
from typing import Dict, Any
from scanner import Scanner, ScanResult
from pydantic import BaseModel

app = FastAPI()
async def scan_url(payload: dict):
    url_to_scan = payload.get("url")
    # ...perform scanning logic...
    return {
        "status": "ok",
        "vulnerabilities": [
            # scanning results...
        ]
    }

class ScanRequest(BaseModel):
    url: str

@app.get("/api/health")
def health_check() -> Dict[str, str]:
    """
    Performs a health check for the backend API.

    Returns:
        Dict[str, str]: A dictionary indicating the health status.
    """
    return {"status": "ok"}

@app.post("/api/scan/", response_model=ScanResult)
async def run_scan(scan_request: ScanRequest) -> ScanResult:
    """
    Initiates a vulnerability scan on the provided URL.

    Args:
        scan_request (ScanRequest): The request body containing the URL to scan.

    Returns:
        ScanResult: The results of the vulnerability scan.

    Raises:
        HTTPException: If there is an error during the scan.
    """
    try:
        scanner = Scanner(scan_request.url)
        results = await scanner.run_all_tests()
        return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
