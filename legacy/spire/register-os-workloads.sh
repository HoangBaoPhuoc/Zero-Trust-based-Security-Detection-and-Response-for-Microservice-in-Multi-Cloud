#!/bin/bash
set -euo pipefail

SPIRE_SERVER_BIN="${SPIRE_SERVER_BIN:-spire-server}"

register() {
	local spiffe_id="$1"
	local parent_id="$2"
	local ns="$3"
	local sa="$4"

	"$SPIRE_SERVER_BIN" entry create \
		-socketPath /tmp/spire-server/private/api.sock \
		-spiffeID "$spiffe_id" \
		-parentID "$parent_id" \
		-selector "k8s:ns:${ns}" \
		-selector "k8s:sa:${sa}" \
		-ttl 3600 || true
}

register "spiffe://ztlab.local/openstack/core-banking" \
	"spiffe://ztlab.local/spire/agent/k8s_psat/os-k3s/spire/spire-agent" \
	"financial" "core-banking"

register "spiffe://ztlab.local/openstack/account-service" \
	"spiffe://ztlab.local/spire/agent/k8s_psat/os-k3s/spire/spire-agent" \
	"financial" "account-service"

register "spiffe://ztlab.local/openstack/transaction-service" \
	"spiffe://ztlab.local/spire/agent/k8s_psat/os-k3s/spire/spire-agent" \
	"financial" "transaction-service"

