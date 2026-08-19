#!/bin/bash
#
# Upgrade the netbox-passwork plugin on a NetBox server.
#
# Usage:
#   sudo ./update.sh            # install the latest release from PyPI
#   sudo ./update.sh v1.1.2     # pin a specific tag/branch/commit from the git repository
#
# Paths can be overridden with environment variables (the defaults match a
# standard NetBox installation):
#   NETBOX_ROOT   (default: /opt/netbox)
#   NETBOX_ENV    (default: /etc/netbox/netbox.env)
#
set -euo pipefail

NETBOX_ROOT="${NETBOX_ROOT:-/opt/netbox}"
NETBOX_ENV="${NETBOX_ENV:-/etc/netbox/netbox.env}"
# Install source: PyPI by default; a ref argument switches to the git repository.
PLUGIN_PACKAGE="netbox-passwork"
PLUGIN_REPO="git+https://github.com/krasotinpa/netbox-passwork-plugin.git"

# Optional argument — a ref (tag/branch/commit) installed from the git repository.
# Without it the plugin is upgraded from PyPI.
REF="${1:-}"
if [ -n "$REF" ]; then
    PLUGIN_SPEC="${PLUGIN_REPO}@${REF}"
else
    PLUGIN_SPEC="$PLUGIN_PACKAGE"
fi

cd "$NETBOX_ROOT"
# shellcheck disable=SC1091
source venv/bin/activate

pip install --upgrade "$PLUGIN_SPEC"

# The plugin needs PW_SESSION_KEY at app load time: the NetBox configuration passes it into the
# required SESSION_ENCRYPT_KEY setting, so even `migrate` fails without it. Read the value from the
# env file of the systemd service (cut -d= -f2- keeps the trailing '=' of the Fernet key).
if [ ! -r "$NETBOX_ENV" ]; then
    echo "ERROR: cannot read $NETBOX_ENV (set NETBOX_ENV or run with sufficient privileges)" >&2
    exit 1
fi
PW_SESSION_KEY="$(grep -E '^PW_SESSION_KEY=' "$NETBOX_ENV" | tail -n1 | cut -d= -f2-)"
export PW_SESSION_KEY
if [ -z "$PW_SESSION_KEY" ]; then
    echo "ERROR: PW_SESSION_KEY not found in $NETBOX_ENV" >&2
    exit 1
fi

python netbox/manage.py migrate netbox_passwork
python netbox/manage.py collectstatic --no-input

echo ""
echo "Done. Restart NetBox to apply:"
echo "  sudo systemctl restart netbox netbox-rq"
