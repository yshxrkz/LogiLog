"""LogiLog: flag suspicious activity in SSH auth.log files."""

from .detectors import Config, Finding, analyze
from .parser import LoginEvent, parse_line, parse_lines

__all__ = ["Config", "Finding", "LoginEvent", "analyze", "parse_line", "parse_lines"]
__version__ = "1.0.0"
