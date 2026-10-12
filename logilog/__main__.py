"""Allows `python -m logilog <logfile>`."""

import sys

from .cli import main

sys.exit(main())
