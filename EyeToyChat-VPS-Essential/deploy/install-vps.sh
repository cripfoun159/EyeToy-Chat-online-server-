#!/bin/sh
set -eu

PREFIX=/opt/eyetoychat
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

mkdir -p "$PREFIX"
cp -a "$SCRIPT_DIR/." "$PREFIX/"

install -m 0644 "$PREFIX/deploy/systemd/eyetoychat.service" /etc/systemd/system/eyetoychat.service

echo "EyeToy Chat installed in $PREFIX"
echo "Next:"
echo "  1. Add the three DNS A records from deploy/bind9/eyetoychat.conf.example"
echo "  2. Enable Apache proxy modules and deploy deploy/apache2/eyetoychat-10443.conf"
echo "  3. systemctl daemon-reload"
echo "  4. systemctl enable --now eyetoychat"
