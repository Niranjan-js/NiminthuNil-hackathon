import re

class PIIFirewall:
    # Aadhaar pattern: 12 digits (often spaced)
    AADHAAR_REGEX = re.compile(r"\b\d{4}\s?\d{4}\s?\d{4}\b")
    # PAN card: 5 letters, 4 digits, 1 letter
    PAN_REGEX = re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b", re.IGNORECASE)
    # Email pattern
    EMAIL_REGEX = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")

    @classmethod
    def redact_pii(cls, text: str) -> str:
        redacted = text
        redacted = cls.AADHAAR_REGEX.sub("[AADHAAR_REDACTED]", redacted)
        redacted = cls.PAN_REGEX.sub("[PAN_REDACTED]", redacted)
        redacted = cls.EMAIL_REGEX.sub("[EMAIL_REDACTED]", redacted)
        return redacted
