"""
`__init__.py` files are demons.  This little demon is here to make sure users
don't import this library the wrong way, risking double-import issues.
"""

import os




raise Exception(
  'Unsupported import path for PyYAUL.  Please add "{}" to your `sys.path` '
  'and import modules using `from pyyaul import ...`.'
  .format(os.path.dirname(__file__)),
)
