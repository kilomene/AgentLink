"""Suite-wide guards.

The in-daemon self-update checker (v1.1.8) must NEVER fire during
the test suite: agents under test would otherwise reach out to the
real update feed. tests/test_self_update.py exercises the checker
explicitly — unit ticks in-process, and one staged subprocess demo
that re-enables it (AGENTLINK_SELF_UPDATE=1) in the CHILD process
environment only.
"""

import os

os.environ["AGENTLINK_SELF_UPDATE"] = "0"
