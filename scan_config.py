"""Shared upload and analysis settings (binary MiB units)."""
MAX_FILE_SIZE = 300 * 1024 * 1024
CHUNK_SIZE = 1024 * 1024
SCAN_TIMEOUT_SECONDS = 120.0
MAX_CONCURRENT_SCANS = 1


def public_config():
    return {"max_file_size_bytes": MAX_FILE_SIZE,
            "max_file_size_label": f"{MAX_FILE_SIZE / 1024 / 1024:g} MiB",
            "scan_timeout_seconds": SCAN_TIMEOUT_SECONDS,
            "max_concurrent_scans": MAX_CONCURRENT_SCANS}
