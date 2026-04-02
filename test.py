#! /usr/bin/env python3.12

from pathlib import Path
import sys

_ROOT = Path(__file__).parent.resolve()
sys.path.append(str(_ROOT))
sys.path.append(str((_ROOT.parent / 'PyYAUL.Base').resolve()))
sys.path.append(str((_ROOT.parent / 'PyYAUL.DB').resolve()))

from pyyaul.base import unittest




if __name__ == '__main__':
	unittest.runTestsIn(_ROOT)
