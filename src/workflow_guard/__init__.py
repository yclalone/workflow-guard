"""workflow-guard public package API."""

from .models import Finding, ScanResult, Severity
from .scanner import scan_path, scan_text

__all__ = ["Finding", "ScanResult", "Severity", "scan_path", "scan_text"]
__version__ = "0.1.0"

