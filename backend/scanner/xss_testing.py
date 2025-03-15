from scanner import VulnerabilityTest, VulnerabilityTestResult
import requests
from urllib.parse import quote

class TestReflectedCrossSiteScripting(VulnerabilityTest):
    """
    Tests for Reflected Cross-Site Scripting (XSS) vulnerabilities.
    """
    async def run(self) -> VulnerabilityTestResult:
        self.log_info("Testing for Reflected XSS...")
        xss_payload = "<script>alert('XSS')</script>"
        encoded_payload = quote(xss_payload) # URL encode payload
        test_url = f"{self.url}?q={encoded_payload}" # Example parameter 'q' - adapt to target app

        try:
            response = self.session.get(test_url, timeout=10, allow_redirects=False)
            if response.status_code == 200 and xss_payload in response.text: # Simple payload reflection check
                return VulnerabilityTestResult(
                    test_name="Test Reflected Cross-Site Scripting (XSS)",
                    severity="high",
                    description="Reflected XSS vulnerability detected. Payload reflected in response.",
                    recommendation="Sanitize user inputs, implement output encoding, and use Content Security Policy (CSP).",
                    vulnerable=True,
                    details={"payload": xss_payload, "reflected_url": test_url}
                )
            else:
                return VulnerabilityTestResult(
                    test_name="Test Reflected Cross-Site Scripting (XSS)",
                    severity="low",
                    description="Reflected XSS vulnerabilities not detected in basic parameter testing.",
                    recommendation="Continue to implement XSS prevention measures and conduct thorough testing.",
                    vulnerable=False
                )
        except requests.RequestException as e:
            self.log_error(f"Request error: {e}", exc_info=True)
            return VulnerabilityTestResult(
                test_name="Test Reflected Cross-Site Scripting (XSS)",
                severity="info", # Info severity as we couldn't reliably check
                description=f"Could not reliably check for reflected XSS due to request error: {e}",
                recommendation="Manually verify and check server logs.",
                vulnerable=False # Cannot confirm vulnerability, so marking as false for now
            )

class TestStoredCrossSiteScripting(VulnerabilityTest):
    """
    Tests for Stored Cross-Site Scripting (XSS) vulnerabilities.
    """
    async def run(self) -> VulnerabilityTestResult:
        self.log_info("Testing for Stored XSS...")
        # Placeholder - Stored XSS testing is application-specific and requires
        # identifying input points that store data and output points that display it.
        # This is a conceptual outline.

        xss_payload = "<script>alert('Stored XSS')</script>"
        vulnerable_input_points = [] # To be populated by identifying input fields/forms

        # Example - simulate posting data to a form (adapt to actual application forms)
        form_input_name = "comment" # Example input field name - customize
        post_data = {form_input_name: xss_payload}

        try:
            # 1. Identify a form/input point that stores data (e.g., comment form, profile update form)
            # 2. Submit the XSS payload to this input point using POST request
            #    (You'll need to handle CSRF tokens if present - outside the scope of this example)
            post_response = self.session.post(self.url, data=post_data, timeout=10, allow_redirects=False) # Replace self.url with form submission URL

            if post_response.status_code in [200, 201, 302]: # Successful post
                # 3. Access the page where the stored data is displayed (output point)
                display_page_response = self.session.get(self.url, timeout=10, allow_redirects=False) # Replace self.url with page where data is displayed
                if display_page_response.status_code == 200 and xss_payload in display_page_response.text:
                    return VulnerabilityTestResult(
                        test_name="Test Stored Cross-Site Scripting (XSS)",
                        severity="critical",
                        description="Stored XSS vulnerability detected. Payload stored and executed.",
                        recommendation="Sanitize user inputs at input and output points, implement output encoding, and use Content Security Policy (CSP).",
                        vulnerable=True,
                        details={"payload": xss_payload, "input_point": self.url, "output_point": self.url} # Update URLs
                    )
        except requests.RequestException as e:
            self.log_error(f"Request error during stored XSS test: {e}", exc_info=True)

        return VulnerabilityTestResult(
            test_name="Test Stored Cross-Site Scripting (XSS)",
            severity="low",
            description="Stored XSS vulnerabilities not detected in basic form submission testing.",
            recommendation="Conduct thorough stored XSS testing, especially on all user-generated content input points.",
            vulnerable=False
        )

# ... (Implement DOM-Based XSS, HTML Injection, CSS Injection, Client Side URL Redirect,
#       Cross Site Flashing, Clickjacking, Cross Site Script Inclusion tests. These often involve
#       client-side analysis or specific header/response checks.) ...