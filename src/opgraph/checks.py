"""Built-in checks for `Engagement.verify`: deterministic proof, never the model's opinion."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from .facts import Fact

if TYPE_CHECKING:
    from .engagement import Engagement, Evidence


class RegexCheck:
    """Confirms a finding when a pattern appears in any observation (e.g. a captured flag or a
    database error string). Evidence records the call and the matched text."""

    def __init__(self, pattern: str, name: str = "regex", flags: int = 0):
        self.pattern = re.compile(pattern, flags)
        self.name = name

    def __call__(self, eng: Engagement, finding: Fact) -> Evidence | None:
        from .engagement import Evidence

        for call_id, text in eng.observations():
            match = self.pattern.search(text)
            if match:
                return Evidence(self.name, f"{call_id}: {match.group(0)[:200]}")
        return None
