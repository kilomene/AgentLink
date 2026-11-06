"""Suite-wide guards.

The in-daemon self-update checker (v1.1.8) is part of the hardened
core (v1.2.0): it has NO agent-side off switch and its 900s interval
cannot be stretched or shrunk from the agent's environment — so it
can never fire inside a test's lifetime (900s >> any test), and no
suite-wide env guard is needed or possible. Staged subprocess demos
in tests/test_self_update.py shorten the interval through a
sitecustomize seam planted on the CHILD's PYTHONPATH by the harness
itself — a test-only reach into the timing constant, not a product
configuration surface.

Workspace isolation (2026-11-05): a client's recovery key is
written to its WORKSPACE (the AGENTLINK_WORKSPACE env route,
default ~/workspace). Test clients that do not pass workspace=
explicitly therefore wrote agentlink-recovery-<user>.txt files
for their scratch identities into the developer's REAL
~/workspace — hundreds accumulated across gate runs. The suite
now points AGENTLINK_WORKSPACE at a session temp directory
unless the caller already set one, so every default-workspace
client lands in scratch space. Tests that assert on the
workspace file pass workspace= explicitly and are unaffected.
"""

import os
import tempfile

os.environ.setdefault(
    "AGENTLINK_WORKSPACE",
    tempfile.mkdtemp(prefix="agentlink-test-workspace-"))
