#!/bin/bash -e

ACCESS_TOKEN=$(./get-at.sh)

echo "AT:" ${ACCESS_TOKEN}

curl -s -X POST "http://localhost:8091/realms/demo/authzen/access/v1/evaluation" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "subject": {
      "type": "user",
      "id": "email:jerry@demo.local"
    },
    "resource": {
      "type": "todo",
      "id": "todo-1"
    },
    "action": {
      "name": "can_read_todos"
    }
  }' | jq