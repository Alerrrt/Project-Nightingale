import logging
from typing import List, Dict, Type, Any, Optional
from abc import ABC, abstractmethod
import asyncio
import requests
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class VulnerabilityTestResult(BaseModel):
    test_name: str
    severity: str
    description: str
    recommendation: str
    vulnerable: bool
    details: Optional[Dict[str, Any]] = None

class ScanResult(BaseModel):
    url: str
    results: List[VulnerabilityTestResult]

class VulnerabilityTest(ABC):
    """
    Abstract base class for vulnerability tests.
    """
    def __init__(self, url: str):
        """
        Initializes a VulnerabilityTest instance.

        Args:
            url (str): The URL to be tested.
        """
        self.url = url
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Project Nightingale Scanner'}) # Setting User-Agent

    @abstractmethod
    async def run(self) -> VulnerabilityTestResult:
        """
        Abstract method to execute the vulnerability test.

        Returns:
            VulnerabilityTestResult: The result of the test.
        """
        pass

    def log_info(self, message: str):
        """Logs an info message with test context."""
        logger.info(f"[{self.__class__.__name__}] {message}")

    def log_warning(self, message: str):
        """Logs a warning message with test context."""
        logger.warning(f"[{self.__class__.__name__}] {message}")

    def log_error(self, message: str, exc_info: bool = False):
        """Logs an error message with test context."""
        logger.error(f"[{self.__class__.__name__}] {message}", exc_info=exc_info)

class Scanner:
    """
    Orchestrates and runs vulnerability tests.
    """
    def __init__(self, url: str):
        """
        Initializes a Scanner instance.

        Args:
            url (str): The URL to be scanned.
        """
        self.url = url
        self.tests: List[VulnerabilityTest] = self._load_tests()

    def _load_tests(self) -> List[VulnerabilityTest]:
        """
        Dynamically loads vulnerability tests.

        Returns:
            List[VulnerabilityTest]: A list of instantiated vulnerability test objects.
        """
        from . import auth_testing, injection_testing, xss_testing, session_testing, business_logic_testing, client_side_testing, tls_testing

        test_modules = [auth_testing, injection_testing, xss_testing, session_testing, business_logic_testing, client_side_testing, tls_testing] # Grouping test modules

        tests = []
        for module in test_modules:
            for name in dir(module):
                obj = getattr(module, name)
                if isinstance(obj, type) and issubclass(obj, VulnerabilityTest) and obj != VulnerabilityTest:
                    try:
                        tests.append(obj(self.url))
                    except Exception as e:
                        logger.error(f"Failed to initialize test {name} from module {module.__name__}: {e}", exc_info=True)
        return tests

    async def run_all_tests(self) -> ScanResult:
        """
        Runs all loaded vulnerability tests asynchronously.

        Returns:
            ScanResult: A ScanResult object containing the results of all tests.
        """
        test_tasks = [test.run() for test in self.tests]
        results = await asyncio.gather(*test_tasks, return_exceptions=True)
        scan_results: List[VulnerabilityTestResult] = []
        for result in results:
            if isinstance(result, VulnerabilityTestResult):
                scan_results.append(result)
            elif isinstance(result, Exception):
                logger.error(f"Test failed and returned exception: {result}", exc_info=True) # Log exceptions from tests
                scan_results.append(VulnerabilityTestResult(
                    test_name="Unknown Test Failure",
                    severity="critical",
                    description=f"A test failed to run due to an error: {type(result).__name__}",
                    recommendation="Check server logs for details.",
                    vulnerable=True, # Assume vulnerable if test failed
                    details={"error": str(result)}
                ))
            else:
                logger.warning(f"Test returned unexpected result type: {type(result).__name__}") # Handle unexpected results

        return ScanResult(url=self.url, results=scan_results)