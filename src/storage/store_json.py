import json
from pathlib import Path
from typing import Dict

def store_json(data: Dict, outpath: str):
    p = Path(outpath)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)
