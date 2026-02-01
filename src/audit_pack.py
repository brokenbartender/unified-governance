from __future__ import annotations

import io
import json
import zipfile


def build_audit_pack(bundle: dict) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("summary.json", json.dumps(bundle, indent=2))
    return buffer.getvalue()
