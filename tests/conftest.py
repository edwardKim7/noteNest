from __future__ import annotations

import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Unit tests only exercise pure file/encoding helpers, so the GUI package is mocked.
sys.modules.setdefault("webview", types.SimpleNamespace())
