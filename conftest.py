import sys
from pathlib import Path

# Lets tests import helpers from scripts/ without packaging them.
sys.path.insert(0, str(Path(__file__).parent / "scripts"))
