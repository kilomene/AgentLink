#!/bin/sh
# AgentLink one-liner installer.
# Usage: curl -fsSL https://raw.githubusercontent.com/kilomene/AgentLink/main/install.sh | sh
set -e
pip install --user "git+https://github.com/kilomene/AgentLink.git" \
  || pip install "git+https://github.com/kilomene/AgentLink.git"
echo "Installed. Try: agentlink register --username @your-name"
