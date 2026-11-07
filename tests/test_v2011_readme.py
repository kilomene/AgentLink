"""2.0.11 — README audit pins (owner's directive, 2026-11-07).

The README was UPDATED to the serverless reality, not rewritten:
everything still needed was kept, every statement of current
behavior corrected, and purely-v1 material moved to a clearly
marked retired appendix at the very end. These pins keep a future
edit from quietly re-teaching the retired line: an agent must be
able to register from this document alone, and the v1 sections
stating relay mechanics in present tense are how Folk's agent got
lost.
"""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
README = (ROOT / "README.md").read_text()
BODY, _, APPENDIX = README.partition(
    "## Retired appendix — the v1 relay line (historical record)")

# Present-tense relay-as-server instructions that must never come
# back into the body (the appendix keeps them as history, under
# its warning banner).
BANNED_IN_BODY = [
    "the relay issues a recovery key",
    "the relay records the grant",
    "the relay verifies it against the registered public key",
    "The relay verifies the signature",
    "The relay **re-offers",
    "the relay resolves the role",
    "the relay reassigns",
    "the relay refuses with the blocker list",
    "the relay acts **only**",
    "the relay proxies every transfer",
    "The relay broker **authorizes**",
    "The relay watches the fleet",
    "The relay rejects plaintext",
    "relay blob layer",
    "relay's welcome frame",
    "relay-advertised key",
    "read live from the relay",
    "stored on its profile by the relay",
    "Registration for new names is not yet open",
    "syncs through the relay",
    "when its server is carried to another host",
]


def test_appendix_exists_at_the_end_under_a_warning():
    assert APPENDIX, "the retired appendix is missing"
    # It is the last content section: only the License follows it.
    tail = README.partition(
        "## Retired appendix — the v1 relay line (historical record)")[2]
    assert tail.index("## License") > 0
    assert "None of it describes current behavior" in APPENDIX
    assert "no relay to run" in APPENDIX


def test_no_v1_sections_left_in_the_body():
    for heading in ("### The peer mesh", "### Server carrying",
                    "### Running a relay", "### Relay and dashboard",
                    "### Stability — the flapping fixes"):
        assert heading not in BODY, heading


def test_no_present_tense_relay_instructions_in_body():
    for phrase in BANNED_IN_BODY:
        assert phrase not in BODY, phrase
    # The false registration claim is banned from the WHOLE
    # document — it contradicted the automatic first-come door.
    assert "Registration for new names is not yet open" not in README


def test_registration_story_is_one_clean_current_path():
    # Automatic first-come registration, the setup flow, and the
    # no-password law are all stated in the body.
    assert "Registration is **automatic and first-come**" in BODY
    assert "agentlink setup" in BODY
    assert "Registration and login NEVER involve a password" in BODY
    # The update semantics of this release are documented too.
    assert "mirror-purges the old tree" in BODY
    assert "self-clean" in BODY
    # And the version badge matches the release.
    assert "version-2.1.0-blue" in BODY
