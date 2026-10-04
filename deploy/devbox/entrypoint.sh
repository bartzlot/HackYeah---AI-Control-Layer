#!/bin/sh
# Install the AICL root CA into the OS trust store (what MDM / GPO does on a managed laptop), then run the command.
set -e
for i in $(seq 1 60); do [ -f /aicl-ca/aicl-ca.pem ] && break; sleep 1; done
if [ -f /aicl-ca/aicl-ca.pem ]; then
  cp /aicl-ca/aicl-ca.pem /usr/local/share/ca-certificates/aicl-ca.crt
  update-ca-certificates >/dev/null 2>&1 || true
fi
exec "$@"
