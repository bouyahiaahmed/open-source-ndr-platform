from __future__ import annotations

import json
from pathlib import Path

from app.config import load_settings
from app.opensearch_client import create_client


def main() -> None:
    settings = load_settings()
    client = create_client(settings)
    mappings_dir = Path(__file__).resolve().parent.parent / "mappings"
    for name, filename in {
        "ndr-behaviors-template": "ndr-behaviors-template.json",
        "ndr-behaviorizer-state-template": "ndr-behaviorizer-state-template.json",
        "ndr-ml-models-template": "ndr-ml-models-template.json",
        "ndr-findings-template": "ndr-findings-template.json",
    }.items():
        body = json.loads((mappings_dir / filename).read_text(encoding="utf-8"))
        client.indices.put_index_template(name=name, body=body)
        print(f"applied {name}")


if __name__ == "__main__":
    main()
