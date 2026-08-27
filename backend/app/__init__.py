# Ensure project root is on PYTHONPATH so that top‑level packages `member3` and `member5` are importable.
import sys
import os

# Add the repository root (two levels up from this file) to sys.path.
repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)
