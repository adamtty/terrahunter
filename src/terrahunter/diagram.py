"""Stage 3b, the diagram: the architecture model as one self-contained HTML page, flat 2D or 3D isometric.

The page loads nothing from the network: its one script is inline, allowed by its hash in a strict Content Security
Policy, and the model rides along as JSON in a non-executing script element (every `<` escaped, so nothing in it can
close the element). Everything from the configuration is drawn as text, never as markup.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from pathlib import Path

from terrahunter import arch, chains

TEMPLATE = Path(__file__).with_name("diagram.html")
STYLE = {  # connection meaning → how it's drawn
    "routes to": "traffic",
    "fronts": "traffic",
    "invokes": "traffic",
    "runs as": "identity",
    "attached": "storage",
    "runs on": "other",
    "signs in to": "identity",
    "assumes": "identity",
    "assumes as guest": "identity",
    "stores in": "storage",
    "runs in": "other",
    "guarded by": "other",
    "configured with": "other",
    "uses": "other",
}
_SCRIPT = re.compile(r"<script>(.*?)</script>", re.DOTALL)  # exactly what the browser hashes


def render(model: arch.Model, title: str, scanned: bool = False, paths: chains.Result | None = None) -> str:
    """The page; `scanned` says whether stage 4 ran, so "no findings" isn't shown when nothing was looked for;
    `paths` (stage 5) adds the internet, the attack paths and the access edges they need."""
    data = model.to_dict()
    for e in data["edges"]:
        e["kind"] = "quiet" if e["quiet"] else STYLE.get(e["label"], "other")
        if e["target"] in {c.id for c in model.components if c.unknown}:
            e["kind"] = "unknown"
    found = paths.to_dict() if paths else {"chains": [], "edges": [], "fixes": [], "leaks": []}
    data["edges"] += found["edges"]
    leaks = [{**c, "leak": True} for c in found.get("leaks", [])]  # after the paths, so fixes' indexes still hold
    data.update(
        target=title,
        chains=found["chains"] + leaks,
        fixes=found["fixes"],
        internet=bool(found["chains"]),
        scanned=scanned,
        walked=paths is not None,
    )
    blob = json.dumps(data).replace("<", "\\u003c")  # nothing in the data can look like markup to the browser
    page = TEMPLATE.read_text(encoding="utf-8").replace("__DATA__", blob)
    script = _SCRIPT.search(page)
    digest = base64.b64encode(hashlib.sha256(script.group(1).encode("utf-8")).digest()).decode()
    return page.replace("__SCRIPT_HASH__", f"sha256-{digest}")
