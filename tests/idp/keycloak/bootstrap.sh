#!/usr/bin/env bash
set -euo pipefail

KCADM=/opt/keycloak/bin/kcadm.sh
SERVER=http://keycloak:8080

log() { echo "[$(date '+%H:%M:%S')] $*"; }

log "Authenticating to Keycloak master realm"
$KCADM config credentials \
  --server "$SERVER" \
  --realm master \
  --user admin \
  --password admin

log "Creating realm 'test'"
$KCADM create realms -s realm=test -s enabled=true
$KCADM update realms/master -s sslRequired=NONE
$KCADM update realms/test -s sslRequired=NONE
$KCADM update realms/test -s accessTokenLifespan=3600

log "Creating client 'test-client'"
$KCADM create clients -r test -f - <<'EOF'
{
  "clientId": "test-client",
  "secret": "test-secret",
  "directAccessGrantsEnabled": true,
  "publicClient": false,
  "clientAuthenticatorType": "client-secret",
  "protocol": "openid-connect",
  "enabled": true
}
EOF

log "Creating realm roles"
$KCADM create roles -r test -s name=mcp-user
$KCADM create roles -r test -s name=mcp-admin

log "Creating user alice (role: mcp-user)"
$KCADM create users -r test \
  -s username=alice -s firstName=Alice -s lastName=Smith \
  -s email=alice@test.local -s emailVerified=true -s enabled=true
$KCADM set-password -r test --username alice --new-password alice123
$KCADM add-roles -r test --uusername alice --rolename mcp-user

log "Creating user bob (role: mcp-admin)"
$KCADM create users -r test \
  -s username=bob -s firstName=Bob -s lastName=Jones \
  -s email=bob@test.local -s emailVerified=true -s enabled=true
$KCADM set-password -r test --username bob --new-password bob123
$KCADM add-roles -r test --uusername bob --rolename mcp-admin

log "Bootstrap complete"
