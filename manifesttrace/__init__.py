"""ManifestTrace: does an Android app's manifest leave something reachable that shouldn't be.

Generalises this author's own CVE-2025-50861 (an exported activity reachable without authentication) and
CVE-2025-50862 (allowBackup=true permitting data extraction over ADB backup) into a scanner that checks a batch
of APKs for the same bug class, instead of reading one manifest by hand. Static analysis only, read-only, no
device or APK is ever modified. A finding is a lead for a human to confirm and responsibly disclose, not proof.
"""
from __future__ import annotations

__version__ = "0.1.0"
__author__ = "Jack Sessions"
__url__ = "https://github.com/JackSessions/manifest-trace"
