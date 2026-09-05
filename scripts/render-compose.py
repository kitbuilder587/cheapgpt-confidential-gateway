import os
import re
import sys
from pathlib import Path

image = os.environ.get("GATEWAY_IMAGE", "")
if not re.fullmatch(r"[a-z0-9./_-]+@sha256:[a-f0-9]{64}", image):
    sys.exit("GATEWAY_IMAGE must be an immutable image digest")
template = Path(__file__).resolve().parents[1] / "deploy" / "compose.yaml"
sys.stdout.write(template.read_text().replace("${GATEWAY_IMAGE:?set an immutable image digest}", image))
