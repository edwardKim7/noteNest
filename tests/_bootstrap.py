"""unittest 스타일 테스트를 위한 공통 부트스트랩.

pytest는 conftest.py를 자동으로 찾아 로드하지만, `python -m unittest`는
그런 자동 로드 메커니즘이 없다. 그래서 각 테스트 파일이 이 모듈을
명시적으로 import해서 동일한 준비 작업(프로젝트 루트를 sys.path에 추가,
GUI 전용 패키지인 webview를 목(mock) 객체로 대체)을 수행한다.

사용법: 각 테스트 파일 맨 위에서
    from tests import _bootstrap  # noqa: F401  (side-effect import)
"""
from __future__ import annotations

import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# 단위 테스트는 순수 파일/암호화 로직만 검증하므로 GUI 패키지(webview)는
# 목(mock) 객체로 대체한다. setdefault라 이미 등록되어 있으면 건드리지 않는다.
sys.modules.setdefault("webview", types.SimpleNamespace())
