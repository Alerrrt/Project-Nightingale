from scanner import VulnerabilityTest, VulnerabilityTestResult
import requests

class TestMissingSecurityHeaders(VulnerabilityTest):
    """
    Tests for the presence of common security headers.
    """
    async def run(self) -> VulnerabilityTestResult:
        self.log_info("Testing for missing security headers...")
        required_headers = {
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'self'", # Basic CSP - customize as needed
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "()", # Empty policy to disable features by default
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload" # HSTS - adjust max-age
        }
        missing_headers = []
        try:
            response = self.session.get(self.url, allow_redirects=True)
            headers = response.headers
            for header, expected_value in required_headers.items():
                if header not in headers:
                    missing_headers.append(header)
        except requests.RequestException as e:
            self.log_error(f"Request error: {e}", exc_info=True)
            return VulnerabilityTestResult(
                test_name="Test Missing Security Headers",
                severity="info", # Info severity as we couldn't reliably check
                description=f"Could not reliably check security headers due to request error: {e}",
                recommendation="Manually verify security headers and check server logs.",
                vulnerable=False # Cannot confirm vulnerability, so marking as false for now
            )

        if missing_headers:
            return VulnerabilityTestResult(
                test_name="Test Missing Security Headers",
                severity="medium",
                description=f"Missing security headers: {missing_headers}",
                recommendation="Implement missing security headers to improve application security.",
                vulnerable=True,
                details={"missing_headers": missing_headers}
            )
        else:
            return VulnerabilityTestResult(
                test_name="Test Missing Security Headers",
                severity="low",
                description="All recommended security headers are present.",
                recommendation="Regularly review and update security header configurations.",
                vulnerable=False
            )

class TestErrorCodes(VulnerabilityTest):
    """
    Tests for verbose error codes that might leak sensitive information.
    """
    async def run(self) -> VulnerabilityTestResult:
        self.log_info("Testing for verbose error codes...")
        # Placeholder - Error code testing requires triggering errors and analyzing responses.
        # This is a simplified example - real error code testing is more nuanced.
        error_inducing_url = f"{self.url}/nonexistent_page" # Example - trigger 404

        try:
            response = self.session.get(error_inducing_url, allow_redirects=False)
            if response.status_code >= 400: # Check for error status codes
                if "exception" in response.text.lower() or "error" in response.text.lower() or "stack trace" in response.text.lower(): # Basic error detail detection
                    return VulnerabilityTestResult(
                        test_name="Test Error Code",
                        severity="medium",
                        description="Verbose error codes detected that might leak sensitive information.",
                        recommendation="Implement custom error pages and avoid displaying detailed error messages in production.",
                        vulnerable=True,
                        details={"status_code": response.status_code, "error_details_present": True}
                    )
                else:
                     return VulnerabilityTestResult(
                        test_name="Test Error Code",
                        severity="low",
                        description="Error responses are generic and likely do not leak sensitive information.",
                        recommendation="Ensure error responses are generic and do not expose internal details.",
                        vulnerable=False,
                        details={"status_code": response.status_code, "error_details_present": False}
                    )
        except requests.RequestException as e:
            self.log_error(f"Request error: {e}", exc_info=True)
            return VulnerabilityTestResult(
                test_name="Test Error Code",
                severity="info", # Info severity as we couldn't reliably check
                description=f"Could not reliably check error codes due to request error: {e}",
                recommendation="Manually verify error handling and check server logs.",
                vulnerable=False # Cannot confirm vulnerability, so marking as false for now
            )

class TestStackTraceExposure(VulnerabilityTest):
    """
    Tests for exposure of stack traces in error responses.
    """
    async def run(self) -> VulnerabilityTestResult:
        # Re-using error code test for stack trace detection as stack traces are often part of verbose errors
        return await TestErrorCodes(self.url).run() # Re-using ErrorCode test for StackTrace for simplicity