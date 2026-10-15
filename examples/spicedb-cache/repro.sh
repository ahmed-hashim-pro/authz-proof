#!/bin/sh
# Reproduces an order-dependent answer in SpiceDB's check cache.
# Needs a fresh SpiceDB with its HTTP gateway on $SPICEDB (default
# http://localhost:8443) and preshared key $KEY (default testkey).
set -eu
S=${SPICEDB:-http://localhost:8443}
K=${KEY:-testkey}
post() { curl -sS -X POST "$S$1" -H "Authorization: Bearer $K" -d "$2"; }
check() {
  post /v1/permissions/check '{"consistency":{"fullyConsistent":true},
    "resource":{"objectType":"document","objectId":"'"$1"'"},"permission":"'"$2"'",
    "subject":{"object":{"objectType":"user","objectId":"alice"}}}' |
  sed -n 's/.*"permissionship":"PERMISSIONSHIP_\([A-Z_]*\)".*/\1/p'
}
post /v1/schema/write '{"schema":"definition user {}\n\ndefinition document {\n\trelation viewer: user\n\trelation editor: user\n\tpermission view_only = viewer - (viewer & editor)\n\tpermission view_and_edit = viewer & editor\n}\n"}' >/dev/null
for doc in one two; do
  post /v1/relationships/write '{"updates":[{"operation":"OPERATION_TOUCH","relationship":{
    "resource":{"objectType":"document","objectId":"'$doc'"},"relation":"viewer",
    "subject":{"object":{"objectType":"user","objectId":"alice"}}}}]}' >/dev/null
done
echo "alice is a viewer of documents one and two, and an editor of neither."
echo "document:one#view_and_edit, asked first:          $(check one view_and_edit)"
echo "document:two#view_only:                           $(check two view_only)"
echo "document:two#view_and_edit, asked after view_only: $(check two view_and_edit)"
