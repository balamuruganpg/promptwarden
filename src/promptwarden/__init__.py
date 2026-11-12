"""PromptWarden scans text for prompt injection and sensitive-data leakage."""

from promptwarden.warden import ScanResult, Warden

__all__ = ["ScanResult", "Warden"]
__version__ = "0.1.0"
