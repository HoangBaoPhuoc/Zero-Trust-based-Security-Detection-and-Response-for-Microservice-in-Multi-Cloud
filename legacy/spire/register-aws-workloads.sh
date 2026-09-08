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

# Each service needs one entry per node agent.
# Node agent IDs are stable per EC2 instance (k8s_psat uses node UID).
# Run: kubectl -n spire exec deploy/spire-server -- spire-server agent list
# to get the current agent SPIFFE IDs for this cluster.
AGENT_GENERIC="spiffe://ztlab.local/spire/agent/k8s_psat/aws-k3s/spire/spire-agent"
AGENT_NODE1="spiffe://ztlab.local/spire/agent/k8s_psat/aws-k3s/3548edb2-d8fb-46e0-a55d-ffd3a4b170c2"
AGENT_NODE2="spiffe://ztlab.local/spire/agent/k8s_psat/aws-k3s/ce6be52e-c114-44fd-a9cc-88a4a5801aef"

for AGENT in "$AGENT_GENERIC" "$AGENT_NODE1" "$AGENT_NODE2"; do
	register "spiffe://ztlab.local/aws/api-gateway"          "$AGENT" "financial" "api-gateway"
	register "spiffe://ztlab.local/aws/payment-service"      "$AGENT" "financial" "payment-service"
	register "spiffe://ztlab.local/aws/fraud-detection"      "$AGENT" "financial" "fraud-detection"
	register "spiffe://ztlab.local/aws/notification-service" "$AGENT" "financial" "notification-service"
	register "spiffe://ztlab.local/aws/core-banking"         "$AGENT" "financial" "core-banking"
	register "spiffe://ztlab.local/aws/account-service"      "$AGENT" "financial" "account-service"
	register "spiffe://ztlab.local/aws/transaction-service"  "$AGENT" "financial" "transaction-service"
	register "spiffe://ztlab.local/aws/web-portal"           "$AGENT" "financial" "web-portal"
done
