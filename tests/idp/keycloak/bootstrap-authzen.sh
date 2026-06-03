#!/usr/bin/env bash
set -euo pipefail

KCADM=/opt/keycloak/bin/kcadm.sh
SERVER=http://keycloak-authzen:8080

log() { echo "[$(date '+%H:%M:%S')] $*"; }

log "Authenticating to keycloak-authzen master realm"
$KCADM config credentials \
  --server "$SERVER" \
  --realm master \
  --user admin \
  --password admin

log "Creating realm 'demo'"
$KCADM create realms -s realm=demo -s enabled=true
$KCADM update realms/master -s sslRequired=NONE
$KCADM update realms/demo   -s sslRequired=NONE
$KCADM update realms/demo   -s accessTokenLifespan=3600

log "Creating realm roles"
$KCADM create roles -r demo -s name=admin
$KCADM create roles -r demo -s name=viewer

log "Creating user rick (role: admin)"
$KCADM create users -r demo \
  -s username=rick -s firstName=Rick -s lastName=Sanchez \
  -s email=rick@demo.local -s emailVerified=true -s enabled=true
$KCADM set-password -r demo --username rick --new-password rick123
$KCADM add-roles    -r demo --uusername rick --rolename admin

log "Creating user jerry (role: viewer)"
$KCADM create users -r demo \
  -s username=jerry -s firstName=Jerry -s lastName=Smith \
  -s email=jerry@demo.local -s emailVerified=true -s enabled=true
$KCADM set-password -r demo --username jerry --new-password jerry123
$KCADM add-roles    -r demo --uusername jerry --rolename viewer

log "Creating client 'demo-client' with Authorization Services enabled"
CLIENT_ID=$($KCADM create clients -r demo \
  -s clientId=demo-client \
  -s secret=demo-secret \
  -s enabled=true \
  -s directAccessGrantsEnabled=true \
  -s serviceAccountsEnabled=true \
  -s authorizationServicesEnabled=true \
  -i)
log "demo-client internal id: $CLIENT_ID"

log "Adding audience mapper so demo-client appears in aud claim (required by Keycloak nightly introspection)"
$KCADM create "clients/$CLIENT_ID/protocol-mappers/models" -r demo \
  -s name=demo-client-audience \
  -s protocol=openid-connect \
  -s protocolMapper=oidc-audience-mapper \
  -s 'config={"included.client.audience":"demo-client","id.token.claim":"false","access.token.claim":"true"}'

log "Creating authorization scopes"
$KCADM create "clients/$CLIENT_ID/authz/resource-server/scope" -r demo -s name=can_read_todos
$KCADM create "clients/$CLIENT_ID/authz/resource-server/scope" -r demo -s name=can_create_todo

log "Creating resource 'todo-1'"
$KCADM create "clients/$CLIENT_ID/authz/resource-server/resource" -r demo \
  -s name=todo-1 \
  -s type=todo \
  -s 'scopes=[{"name":"can_read_todos"},{"name":"can_create_todo"}]'

log "Creating role-based policies"
$KCADM create "clients/$CLIENT_ID/authz/resource-server/policy/role" -r demo \
  -s name=admin-policy \
  -s 'roles=[{"id":"admin"}]'

$KCADM create "clients/$CLIENT_ID/authz/resource-server/policy/role" -r demo \
  -s name=viewer-policy \
  -s 'roles=[{"id":"viewer"}]'

log "Creating scope permissions"

# can_read_todos: admin + viewer can read
$KCADM create "clients/$CLIENT_ID/authz/resource-server/permission/scope" -r demo \
  -s name=read-todos-permission \
  -s decisionStrategy=AFFIRMATIVE \
  -s 'resources=["todo-1"]' \
  -s 'scopes=["can_read_todos"]' \
  -s 'policies=["admin-policy","viewer-policy"]'

# can_create_todo: admin only
$KCADM create "clients/$CLIENT_ID/authz/resource-server/permission/scope" -r demo \
  -s name=create-todo-permission \
  -s 'resources=["todo-1"]' \
  -s 'scopes=["can_create_todo"]' \
  -s 'policies=["admin-policy"]'

log "Creating client 'gateway-client' for OAuth2 PDP auth (20 s token lifetime for renewal tests)"
GATEWAY_CLIENT_ID=$($KCADM create clients -r demo \
  -s clientId=gateway-client \
  -s secret=gateway-secret \
  -s enabled=true \
  -s serviceAccountsEnabled=true \
  -s authorizationServicesEnabled=true \
  -s 'attributes={"access.token.lifespan":"20"}' \
  -i)
log "gateway-client internal id: $GATEWAY_CLIENT_ID"

log "Mirroring authorization scopes, resource, and policies on gateway-client"
$KCADM create "clients/$GATEWAY_CLIENT_ID/authz/resource-server/scope" -r demo -s name=can_read_todos
$KCADM create "clients/$GATEWAY_CLIENT_ID/authz/resource-server/scope" -r demo -s name=can_create_todo

$KCADM create "clients/$GATEWAY_CLIENT_ID/authz/resource-server/resource" -r demo \
  -s name=todo-1 \
  -s type=todo \
  -s 'scopes=[{"name":"can_read_todos"},{"name":"can_create_todo"}]'

$KCADM create "clients/$GATEWAY_CLIENT_ID/authz/resource-server/policy/role" -r demo \
  -s name=admin-policy \
  -s 'roles=[{"id":"admin"}]'

$KCADM create "clients/$GATEWAY_CLIENT_ID/authz/resource-server/policy/role" -r demo \
  -s name=viewer-policy \
  -s 'roles=[{"id":"viewer"}]'

$KCADM create "clients/$GATEWAY_CLIENT_ID/authz/resource-server/permission/scope" -r demo \
  -s name=read-todos-permission \
  -s decisionStrategy=AFFIRMATIVE \
  -s 'resources=["todo-1"]' \
  -s 'scopes=["can_read_todos"]' \
  -s 'policies=["admin-policy","viewer-policy"]'

$KCADM create "clients/$GATEWAY_CLIENT_ID/authz/resource-server/permission/scope" -r demo \
  -s name=create-todo-permission \
  -s 'resources=["todo-1"]' \
  -s 'scopes=["can_create_todo"]' \
  -s 'policies=["admin-policy"]'

log "Bootstrap complete: demo realm with rick (admin), jerry (viewer), demo-client, and gateway-client ready"
