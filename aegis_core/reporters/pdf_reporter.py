"""
PDF Reporter for AegisSec using Headless Chrome / Chromium.
Generates an executive-grade PDF document directly from the HTML report.
"""

import os
import sys
import shutil
import subprocess
from typing import Optional


def find_chrome_binary() -> Optional[str]:
    """Finds available Chrome / Chromium executable across operating systems."""
    # Common locations on macOS
    macos_paths = [
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/Applications/Chromium.app/Contents/MacOS/Chromium",
        "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
        "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
    ]
    for p in macos_paths:
        if os.path.exists(p) and os.access(p, os.X_OK):
            return p

    # PATH checks (Linux / Windows / macOS PATH)
    for bin_name in ["google-chrome", "chromium", "chromium-browser", "google-chrome-stable", "brave-browser"]:
        found = shutil.which(bin_name)
        if found:
            return found

    return None


class PDFReporter:
    def __init__(self, html_filepath: str):
        self.html_filepath = os.path.abspath(html_filepath)

    def generate(self, output_pdf_path: str) -> bool:
        """Converts the HTML report into a professional PDF."""
        chrome_bin = find_chrome_binary()
        if not chrome_bin:
            return False

        abs_output_pdf = os.path.abspath(output_pdf_path)
        os.makedirs(os.path.dirname(abs_output_pdf), exist_ok=True)

        cmd = [
            chrome_bin,
            "--headless",
            "--disable-gpu",
            "--no-pdf-header-footer",
            "--user-data-dir=/tmp/aegis_chrome_profile",
            f"--print-to-pdf={abs_output_pdf}",
            f"file://{self.html_filepath}",
        ]

        try:
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
            return os.path.exists(abs_output_pdf) and os.path.getsize(abs_output_pdf) > 0
        except Exception:
            return False
