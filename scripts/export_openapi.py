import json
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.app import app


def main() -> None:
    spec = app.openapi()
    out_path = os.path.join("docs", "openapi.json")
    with open(out_path, "w", encoding="utf-8") as handle:
        json.dump(spec, handle, indent=2)
    print(f"Wrote {out_path}")


if __name__ == "__main__":
    main()
