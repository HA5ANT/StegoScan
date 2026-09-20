"""StegoScan — steganography triage for CTF, pentest and forensic workflows.

Pure standard library by design: it runs from a clone with no install step, so
it works in air-gapped labs and on locked-down examiner workstations.
"""

from .runner import VERSION, scan_file

__version__ = VERSION
__all__ = ["scan_file", "VERSION", "__version__"]
