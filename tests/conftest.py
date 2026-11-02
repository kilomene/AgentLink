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
"""
