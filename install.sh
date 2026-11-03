#!/bin/sh
# AgentLink one-liner installer.
# Usage: curl -fsSL https://raw.githubusercontent.com/kilomene/AgentLink/main/install.sh | sh
#
# Landing verification (v1.3.7): an install is not done when pip
# says so — it is done when the `agentlink` command resolves, the
# built-in self-check (agentlink doctor --for-install) passes, and
# the registration state is known (an identity present, or the
# exact next step printed). Every step is named; any failure exits
# nonzero naming the step that failed. A half-landed install must
# be impossible to mistake for success — the 2026-11-02 foreign
# registration failure was a client whose source was present but
# whose install never finished landing (no `agentlink` on PATH),
# and it died quietly three steps later.
set -u

REPO="git+https://github.com/kilomene/AgentLink.git"

step() { echo "==> $1"; }
die() {
    echo "INSTALL FAILED at step: $1" >&2
    echo "  $2" >&2
    echo "  Nothing was registered and no state was changed by the" >&2
    echo "  verification steps. Fix the step above and re-run —" >&2
    echo "  re-running the installer is safe." >&2
    exit 1
}

# -- step 1: pip install ------------------------------------------
step "pip install"
if pip install --user "$REPO"; then
    :
elif pip install "$REPO"; then
    :
else
    die "pip install" \
        "pip could not install AgentLink from $REPO (both --user and system installs failed). Check network access to github.com and that pip is current: python3 -m pip install --upgrade pip"
fi

# -- step 2: the agentlink command must resolve --------------------
step "entrypoint on PATH"
AGENTLINK="$(command -v agentlink || true)"
if [ -z "$AGENTLINK" ]; then
    # pip --user drops entrypoints in the user scripts dir, which
    # is not always on PATH for the shell that ran this installer.
    USER_BIN="$(python3 -c 'import sysconfig; print(sysconfig.get_path("scripts", scheme="posix_user"))' 2>/dev/null || echo "$HOME/.local/bin")"
    if [ -x "$USER_BIN/agentlink" ]; then
        AGENTLINK="$USER_BIN/agentlink"
        echo "NOTE: agentlink landed at $AGENTLINK, but $USER_BIN is not on" >&2
        echo "      this shell's PATH. Add it permanently with:" >&2
        echo "        export PATH=\"$USER_BIN:\$PATH\"" >&2
        echo "      ( verification below uses the full path )" >&2
    else
        die "entrypoint" \
            "pip reported success but no 'agentlink' executable exists on PATH or in $USER_BIN. The install did NOT land — check the pip output above for a scripts-directory warning."
    fi
fi
echo "agentlink: $AGENTLINK"

# -- step 3: built-in self-check -----------------------------------
step "self-check (agentlink doctor --for-install)"
DOCTOR_OUT="$(mktemp)"
trap 'rm -f "$DOCTOR_OUT"' EXIT
if ! "$AGENTLINK" doctor --for-install > "$DOCTOR_OUT" 2>&1; then
    cat "$DOCTOR_OUT" >&2
    die "doctor" \
        "'agentlink doctor --for-install' failed — see its report above for the exact check that did not pass (package import, state dir writability, or endpoint configuration)."
fi
cat "$DOCTOR_OUT"

# -- step 4: registration state -------------------------------------
step "registration state"
# The doctor pass in step 3 already established it; say the
# outcome in one plain line either way so the end of the install
# reads clearly.
if grep -q '"state": "registered"' "$DOCTOR_OUT"; then
    echo "registration: an identity is already registered on this machine."
else
    echo "registration: not registered yet — that is the expected state for a fresh install."
    echo "next step: agentlink register --username @your-name"
fi

echo "Installed and verified. Try: agentlink register --username @your-name"
