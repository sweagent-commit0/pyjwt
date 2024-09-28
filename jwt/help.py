import json
import platform
import sys
from typing import Dict
from . import __version__ as pyjwt_version
try:
    import cryptography
    cryptography_version = cryptography.__version__
except ModuleNotFoundError:
    cryptography_version = ''

def info() -> Dict[str, Dict[str, str]]:
    """
    Generate information for a bug report.
    Based on the requests package help utility module.
    """
    pass

def main() -> None:
    """Pretty-print the bug information as JSON."""
    pass
if __name__ == '__main__':
    main()