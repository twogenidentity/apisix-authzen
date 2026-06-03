#!/bin/bash -e

# Obtain an access token for the authzen-pdp client using the client credentials grant.
# This token is required to authenticate requests to the AuthZEN Evaluation API.

curl -s -X POST "http://localhost:8091/realms/demo/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d 'grant_type=client_credentials&client_id=demo-client&client_secret=demo-secret' \
  | jq -r .access_token