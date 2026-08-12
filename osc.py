#!/usr/bin/env python3
"""
OSC - Open Source Code Scanner
Backward-compatible launcher. The implementation now lives in the `osc/` package.

Run either of:
    python3 osc.py [OPTIONS] TARGET_URL
    python -m osc  [OPTIONS] TARGET_URL

Author : mamay
Legal  : only scan targets you own or have explicit written permission to test.
"""

from osc.cli import main

if __name__ == "__main__":
    main()
