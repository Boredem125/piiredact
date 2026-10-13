import sys
from pathlib import Path

# Lets tests and benchmarks share the synthetic data generator in synth.py.
sys.path.insert(0, str(Path(__file__).parent))
