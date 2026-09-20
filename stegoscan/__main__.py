"""Entry point for ``python -m stegoscan``."""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
