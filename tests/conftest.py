import sys
from pathlib import Path

# make the repo root importable no matter where pytest is invoked from
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
