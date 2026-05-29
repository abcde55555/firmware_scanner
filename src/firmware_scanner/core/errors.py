"""Exception hierarchy for the RTOS firmware analyzer."""


class RTOSAnalyzerError(Exception):
    """Base exception for all tool errors."""

    exit_code: int = 1


class FirmwareLoadError(RTOSAnalyzerError):
    """Firmware file cannot be loaded."""

    exit_code = 2


class FirmwareCorruptedError(RTOSAnalyzerError):
    """Firmware file is corrupted or truncated."""

    exit_code = 0


class UnsupportedFormatError(RTOSAnalyzerError):
    """No format handler can parse this firmware."""

    exit_code = 3


class ExternalToolMissingError(RTOSAnalyzerError):
    """Required external tool not found."""

    exit_code = 0


class ArchDetectionFailedError(RTOSAnalyzerError):
    """Could not determine CPU architecture."""

    exit_code = 0


class ExtractionError(RTOSAnalyzerError):
    """Extraction stage failed."""

    exit_code = 0
