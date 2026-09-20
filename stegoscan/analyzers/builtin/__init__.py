"""Builtin analyzers: no external tools, no third-party imports.

Import order is registration order, which is also report order. Identification
first, then structural evidence, then content.
"""

from . import fileinfo  # noqa: F401
from . import signatures  # noqa: F401
from . import appended  # noqa: F401
from . import entropy  # noqa: F401
from . import flags  # noqa: F401
from . import strings_  # noqa: F401
from . import base64_  # noqa: F401
