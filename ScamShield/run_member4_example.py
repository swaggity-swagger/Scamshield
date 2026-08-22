"""Run the ScamShield workflow against the supplied Member 4 example image."""

import json
from pathlib import Path

from scamshield import run_scamshield_workflow


SAMPLE_IMAGE = Path(r"C:\Users\admin\Desktop\SIH\test_images\scam_combined.png")


def main() -> None:
    result = run_scamshield_workflow(SAMPLE_IMAGE, preferred_language="en")
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
