"""Entry point for ``python3 -m stegoscan``.

Also tolerates ``python3 stegoscan`` and ``python3 stegoscan/__main__.py``.
Python will happily execute a directory's ``__main__.py`` directly, but does so
with no package context, and the relative import then fails with an ImportError
that says nothing useful about the real problem. Running from an install-free
clone is the documented path, so the invocation people actually type has to
work.
"""

import os
import sys

if __package__:
    from .cli import main
else:
    # Executed as a plain script: put the repo root on sys.path, import absolutely.
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from stegoscan.cli import main

if __name__ == "__main__":
    sys.exit(main())
