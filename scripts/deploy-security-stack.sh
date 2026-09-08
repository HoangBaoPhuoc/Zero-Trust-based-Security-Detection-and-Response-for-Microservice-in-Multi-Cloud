#!/bin/bash
# Deploy SPIRE / OPA / Envoy / Keycloak security stack
# Run this after K3s clusters are ready and tunnel is up

set -e

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
AWS_CONTEXT="ctx-aws"
OS_CONTEXT="ctx-openstack"
TIMEOUT_WAIT=180
TIMEOUT_KEYCLOAK=300  # Keycloak can take longer to start on first deployment
VERIFY_FAILED=0

log_info() {
  echo "[INFO] $*"
}

log_error() {
  echo "[ERROR] $*" >&2
}

log_step() {
  echo ""
  echo "================================"
  echo "STEP: $*"
  echo "================================"
}

check_rollout() {
  local ctx="$1"
  local ns="$2"
  local kind="$3"
  local name="$4"
  local timeout="$5"
  local critical="$6"

  log_info "Checking rollout: ${kind}/${name} in ${ctx}/${ns} (timeout ${timeout})"
  if kubectl --context "$ctx" -n "$ns" rollout status "${kind}/${name}" --timeout="$timeout" >/dev/null 2>&1; then
    log_info "✓ ${kind}/${name} is ready in ${ctx}/${ns}"
  else
    log_error "${kind}/${name} is not ready in ${ctx}/${ns}"
    if [ "$critical" = "true" ]; then
      VERIFY_FAILED=1
    fi
  fi
}

check_daemonset_ready() {
  local ctx="$1"
  local ns="$2"
  local name="$3"
  local critical="$4"
  local desired ready

  kubectl --context "$ctx" -n "$ns" rollout status "daemonset/${name}" --timeout="${TIMEOUT_WAIT}s" >/dev/null 2>&1 || true

  desired=$(kubectl --context "$ctx" -n "$ns" get ds "$name" -o jsonpath='{.status.desiredNumberScheduled}' 2>/dev/null || echo "0")
  ready=$(kubectl --context "$ctx" -n "$ns" get ds "$name" -o jsonpath='{.status.numberReady}' 2>/dev/null || echo "0")

  if [ "$desired" -gt 0 ] && [ "$desired" = "$ready" ]; then
    log_info "✓ daemonset/${name} ready ${ready}/${desired} in ${ctx}/${ns}"
  else
    log_error "daemonset/${name} not ready ${ready}/${desired} in ${ctx}/${ns}"
    if [ "$critical" = "true" ]; then
      VERIFY_FAILED=1
    fi
  fi
}

check_configmap() {
  local ctx="$1"
  local ns="$2"
  local name="$3"

  if kubectl --context "$ctx" -n "$ns" get cm "$name" >/dev/null 2>&1; then
    log_info "✓ configmap/${name} exists in ${ctx}/${ns}"
  else
    log_error "configmap/${name} missing in ${ctx}/${ns}"
    VERIFY_FAILED=1
  fi
}

check_kctl_context() {
  if ! kubectl --context "$1" cluster-info >/dev/null 2>&1; then
    log_error "Cannot reach kubectl context $1. Run: ./scripts/k8s-tunnel.sh up"
    exit 1
  fi
}

financial_manifests_ready() {
  local manifests=(
    "$REPO_ROOT/k8s/financial/aws-services.yaml"
    "$REPO_ROOT/k8s/financial/os-services.yaml"
  )
  for f in "${manifests[@]}"; do
    if [ ! -f "$f" ] || ! grep -qE '^apiVersion:' "$f"; then
      return 1
    fi
  done
  return 0
}

random_secret() {
  openssl rand -base64 32 2>/dev/null || date +%s%N
}

ensure_keycloak_secret() {
  if kubectl --context $AWS_CONTEXT -n identity get secret keycloak-secret >/dev/null 2>&1; then
    log_info "Keycloak secret already exists"
    return
  fi

  local admin_password postgres_password
  admin_password="${KEYCLOAK_ADMIN_PASSWORD:-$(random_secret)}"
  postgres_password="${KEYCLOAK_DB_PASSWORD:-$(random_secret)}"

  kubectl --context $AWS_CONTEXT -n identity create secret generic keycloak-secret \
    --from-literal=admin-password="$admin_password" \
    --from-literal=postgres-password="$postgres_password"
  log_info "Created keycloak-secret from environment/random values"
}

deploy_step_1_namespaces() {
  log_step "1. Create Namespaces"

  log_info "Creating namespaces on AWS cluster..."
  kubectl --context $AWS_CONTEXT apply -f "$REPO_ROOT/k8s/namespaces.yaml"

  log_info "Creating namespaces on OpenStack cluster..."
  kubectl --context $OS_CONTEXT apply -f "$REPO_ROOT/k8s/namespaces.yaml"

  sleep 3
  log_info "Namespaces created successfully"
}

deploy_step_2_keycloak() {
  log_step "2. Deploy Keycloak (AWS only)"

  log_info "Creating Keycloak secrets..."
  ensure_keycloak_secret

  log_info "Deploying Keycloak PostgreSQL..."
  kubectl --context $AWS_CONTEXT apply -f "$REPO_ROOT/k8s/keycloak/postgres.yaml"

  log_info "Keycloak DB deployment initiated (waiting up to 60s - in lab it may timeout, that's OK)..."
  kubectl --context $AWS_CONTEXT wait --for=condition=Ready pod \
    -l app=keycloak-db -n identity --timeout=60s 2>/dev/null || {
    log_info "DB pod still starting (node may be recovering - this is normal in lab environment)"
  }

  log_info "Deploying Keycloak server..."
  # realm-config.json is the single source of truth. It used to also be
  # hand-embedded inline in realm-configmap.yaml (kubectl apply -f), which
  # went stale (e.g. missing port-forward redirect URIs added later, missing
  # the demoadmin user added only to the embedded copy) because nobody
  # remembered to edit both. Generate the ConfigMap from the file directly so
  # there is exactly one place to edit.
  log_info "Deploying Keycloak realm config..."
  kubectl --context $AWS_CONTEXT -n identity create configmap keycloak-realm-config \
    --from-file=realm-config.json="$REPO_ROOT/k8s/keycloak/realm-config.json" \
    --dry-run=client -o yaml | kubectl --context $AWS_CONTEXT apply -f -

  kubectl --context $AWS_CONTEXT apply -f "$REPO_ROOT/k8s/keycloak/deployment.yaml"
  kubectl --context $AWS_CONTEXT apply -f "$REPO_ROOT/k8s/keycloak/service.yaml"

  log_info "Keycloak deployment initiated (can take 5-10 minutes on first startup with DB setup)"
  log_info "Note: Keycloak is not a blocking dependency for SPIRE/OPA, so we proceed with deployment"
  log_info "To wait for Keycloak readiness manually:"
  log_info "  kubectl --context ctx-aws wait --for=condition=Ready pod -l app=keycloak -n identity --timeout=600s"
  
  # Don't block on Keycloak startup in lab environment
  # kubectl --context $AWS_CONTEXT wait --for=condition=Ready pod \
  #   -l app=keycloak -n identity --timeout=${TIMEOUT_KEYCLOAK}s || {
  #   log_error "Keycloak Pod failed to start within ${TIMEOUT_KEYCLOAK}s. Checking logs for details..."
  #   kubectl --context $AWS_CONTEXT logs -l app=keycloak -n identity --tail=50
  #   exit 1
  # }

  log_info "Keycloak deployment completed"
}

provision_spire_root_ca() {
  log_step "3.0 Provision shared SPIRE root CA"

  local ca_dir="$REPO_ROOT/spire/root-ca"
  mkdir -p "$ca_dir"

  if [[ ! -f "$ca_dir/ca.key" || ! -f "$ca_dir/ca.crt" ]]; then
    log_info "Generating shared root CA for cross-cloud mTLS trust..."
    openssl genrsa -out "$ca_dir/ca.key" 4096 2>/dev/null
    # -extensions v3_ca alone (no -config) silently relies on whatever
    # [v3_ca] section exists in the system's default openssl.cnf, which does
    # not reliably include keyUsage. A root CA without keyUsage=keyCertSign
    # fails RFC 5280 strict validation — invisible to this project's
    # hand-rolled Envoy (lenient validation_context) but rejected outright by
    # Istio's SPIFFE cert validator (used for every Istio-managed mTLS
    # handshake), causing connections to silently fail. -addext is explicit
    # and doesn't depend on any external config file.
    openssl req -new -x509 -days 3650 -key "$ca_dir/ca.key" \
      -out "$ca_dir/ca.crt" \
      -subj "/C=VN/O=ZT-Lab/CN=ZTLab Root CA" \
      -addext "basicConstraints=critical,CA:TRUE" \
      -addext "keyUsage=critical,keyCertSign,cRLSign" \
      -addext "subjectKeyIdentifier=hash" 2>/dev/null
    log_info "Root CA generated: $ca_dir/ca.crt"
  else
    log_info "Root CA already exists, reusing: $ca_dir/ca.crt"
  fi

  log_info "Deploying spire-upstream-ca secret to both clusters..."
  for CTX in "$AWS_CONTEXT" "$OS_CONTEXT"; do
    kubectl --context "$CTX" apply -f "$REPO_ROOT/spire/k8s/namespace.yaml"
    kubectl --context "$CTX" create secret generic spire-upstream-ca -n spire \
      --from-file=ca.key="$ca_dir/ca.key" \
      --from-file=ca.crt="$ca_dir/ca.crt" \
      --dry-run=client -o yaml | kubectl --context "$CTX" apply -f -
  done
  log_info "spire-upstream-ca secret deployed to both clusters"
}

deploy_step_3_spire_aws() {
  log_step "3.1 Deploy SPIRE on AWS"

  log_info "Creating SPIRE namespace + RBAC..."
  kubectl --context $AWS_CONTEXT apply -f "$REPO_ROOT/spire/k8s/namespace.yaml"
  kubectl --context $AWS_CONTEXT apply -f "$REPO_ROOT/spire/k8s/rbac.yaml"

  log_info "Creating SPIRE configmaps on AWS..."
  kubectl --context $AWS_CONTEXT -n spire create configmap spire-server-config \
    --from-file=server.conf="$REPO_ROOT/spire/server/aws-server.conf" \
    --dry-run=client -o yaml | kubectl --context $AWS_CONTEXT apply -f -
  kubectl --context $AWS_CONTEXT -n spire create configmap spire-agent-config \
    --from-file=agent.conf="$REPO_ROOT/spire/agent/aws-agent.conf" \
    --dry-run=client -o yaml | kubectl --context $AWS_CONTEXT apply -f -
  # T-2.1: root CA agents dùng để verify server khi bootstrap (thay
  # insecure_bootstrap) — cùng CA server.conf dùng làm UpstreamAuthority.
  kubectl --context $AWS_CONTEXT -n spire create configmap spire-bundle \
    --from-file=ca.crt="$REPO_ROOT/spire/root-ca/ca.crt" \
    --dry-run=client -o yaml | kubectl --context $AWS_CONTEXT apply -f -

  log_info "Labeling nodes for SPIRE server on AWS..."
  SECURITY_NODE=$(kubectl --context $AWS_CONTEXT get nodes --no-headers \
    -o custom-columns=NAME:.metadata.name | head -1)
  if [ -z "$SECURITY_NODE" ]; then
    log_error "No nodes found in AWS cluster"
    exit 1
  fi
  kubectl --context $AWS_CONTEXT label node "$SECURITY_NODE" spire-server=true --overwrite

  log_info "Deploying SPIRE server..."
  kubectl --context $AWS_CONTEXT apply -f "$REPO_ROOT/spire/k8s/server-deployment.yaml"
  kubectl --context $AWS_CONTEXT -n spire rollout restart deployment/spire-server >/dev/null 2>&1 || true

  log_info "Waiting for SPIRE server to be ready (timeout: 60s, may skip if tunnel unstable)..."
  kubectl --context $AWS_CONTEXT wait --for=condition=Ready pod \
    -l app=spire-server -n spire --timeout=60s 2>/dev/null || {
    log_info "SPIRE server still starting (tunnel may be unstable - check manually if issue persists)"
  }

  log_info "Deploying SPIRE agents..."
  kubectl --context $AWS_CONTEXT apply -f "$REPO_ROOT/spire/k8s/agent-daemonset.yaml"
  kubectl --context $AWS_CONTEXT -n spire rollout restart daemonset/spire-agent >/dev/null 2>&1 || true

  log_info "SPIRE agents deployment initiated (may take time - skipping strict wait for lab stability)"

  log_info "SPIRE on AWS deployment completed"
}

deploy_step_3_spire_os() {
  log_step "3.2 Deploy SPIRE on OpenStack"

  log_info "Creating SPIRE namespace + RBAC..."
  kubectl --context $OS_CONTEXT apply -f "$REPO_ROOT/spire/k8s/namespace.yaml"
  kubectl --context $OS_CONTEXT apply -f "$REPO_ROOT/spire/k8s/rbac.yaml"

  log_info "Creating SPIRE configmaps on OpenStack..."
  kubectl --context $OS_CONTEXT -n spire create configmap spire-server-config \
    --from-file=server.conf="$REPO_ROOT/spire/server/os-server.conf" \
    --dry-run=client -o yaml | kubectl --context $OS_CONTEXT apply -f -
  kubectl --context $OS_CONTEXT -n spire create configmap spire-agent-config \
    --from-file=agent.conf="$REPO_ROOT/spire/agent/os-agent.conf" \
    --dry-run=client -o yaml | kubectl --context $OS_CONTEXT apply -f -
  # T-2.1: xem giải thích trong deploy_step_3_spire_aws — cùng CA cho cả 2 cluster.
  kubectl --context $OS_CONTEXT -n spire create configmap spire-bundle \
    --from-file=ca.crt="$REPO_ROOT/spire/root-ca/ca.crt" \
    --dry-run=client -o yaml | kubectl --context $OS_CONTEXT apply -f -

  log_info "Labeling nodes for SPIRE server on OpenStack..."
  IDENTITY_NODE=$(kubectl --context $OS_CONTEXT get nodes --no-headers \
    -o custom-columns=NAME:.metadata.name | head -1)
  if [ -z "$IDENTITY_NODE" ]; then
    log_error "No nodes found in OpenStack cluster"
    exit 1
  fi
  kubectl --context $OS_CONTEXT label node "$IDENTITY_NODE" spire-server=true --overwrite

  log_info "Deploying SPIRE server..."
  kubectl --context $OS_CONTEXT apply -f "$REPO_ROOT/spire/k8s/server-deployment.yaml"
  kubectl --context $OS_CONTEXT -n spire rollout restart deployment/spire-server >/dev/null 2>&1 || true

  log_info "Waiting for SPIRE server to be ready (timeout: 60s, may skip if tunnel unstable)..."
  kubectl --context $OS_CONTEXT wait --for=condition=Ready pod \
    -l app=spire-server -n spire --timeout=60s 2>/dev/null || {
    log_info "SPIRE server still starting (tunnel may be unstable)"
  }

  log_info "Deploying SPIRE agents..."
  kubectl --context $OS_CONTEXT apply -f "$REPO_ROOT/spire/k8s/agent-daemonset.yaml"
  kubectl --context $OS_CONTEXT -n spire rollout restart daemonset/spire-agent >/dev/null 2>&1 || true

  log_info "SPIRE agents deployment initiated on OpenStack"

  log_info "SPIRE on OpenStack deployment completed"
}

deploy_step_4_opa() {
  log_step "4. Deploy OPA (Open Policy Agent)"

  log_info "Creating OPA config/policy configmaps on AWS..."
  kubectl --context $AWS_CONTEXT -n financial create configmap opa-config \
    --from-file=opa-config.yaml="$REPO_ROOT/opa/config/opa-config.yaml" \
    --dry-run=client -o yaml | kubectl --context $AWS_CONTEXT apply -f -
  kubectl --context $AWS_CONTEXT -n financial create configmap opa-policies \
    --from-file="$REPO_ROOT/opa/policies" \
    --dry-run=client -o yaml | kubectl --context $AWS_CONTEXT apply -f -

  log_info "Deploying OPA on AWS..."
  kubectl --context $AWS_CONTEXT apply -f "$REPO_ROOT/opa/deployment.yaml"

  # OS opa-config ConfigMap is defined inline in os-security.yaml (its
  # ext_authz path differs from AWS's: zta/crosscloud/allow vs zta/authz/allow).
  # The rego policies themselves must come from this single --from-file step —
  # os-security.yaml intentionally does NOT define its own opa-policies
  # ConfigMap anymore (see comment there) so this is the sole source for OS.
  kubectl --context $OS_CONTEXT -n financial create configmap opa-policies \
    --from-file="$REPO_ROOT/opa/policies" \
    --dry-run=client -o yaml | kubectl --context $OS_CONTEXT apply -f -

  log_info "OPA deployed on AWS; OS OPA (opa-config) will be configured by os-security.yaml"
}

# deploy_step_5_envoy() removed (Phase 6 cleanup): all 8 financial services
# on both clouds are migrated to Istio — nothing mounts the envoy-config
# ConfigMap anymore (istio-proxy replaces the hand-rolled Envoy sidecar
# entirely, SPIRE stays the cert source via the Workload API socket instead
# of this ConfigMap's SDS cluster definitions). envoy/configmap.yaml is kept
# in the repo as a historical reference for the pre-Istio mTLS/ext_authz
# design, but is no longer applied by any deploy script.

# Actual registration logic lives in scripts/ensure-spire-entries.sh —
# shared with deploy-app.sh's deploy_financial_services(), which also calls
# it on EVERY run (not just this one-time security-stack pass). Reason: the
# SPIRE datastore (sqlite3 on a node-pinned hostPath, see k8s/spire/*.yaml)
# has no automatic backup — if spire-server is ever recreated in a way that
# loses that hostPath content, every workload entry vanishes silently
# (observed once in practice: pod recreated ~93min into a session with 0
# registration entries left) and istio-proxy's SPIRE-backed SDS starts
# failing ("workload is not authorized for the requested identities") for
# any pod created after the wipe, while already-running pods keep working
# off their cached SVID — a delayed, confusing failure mode. Re-running this
# script on every deploy-app.sh invocation self-heals a wiped datastore on
# the next redeploy instead of waiting for someone to notice a broken pod.
register_spire_workloads() {
  log_step "3.3 Register SPIRE workload entries"
  AWS_CONTEXT="$AWS_CONTEXT" OS_CONTEXT="$OS_CONTEXT" TIMEOUT_WAIT="$TIMEOUT_WAIT" \
    "$REPO_ROOT/scripts/ensure-spire-entries.sh"
}

deploy_security_healthcheck() {
  log_step "3.4 Deploy security control-plane health-check"

  kubectl --context "$AWS_CONTEXT" apply -f "$REPO_ROOT/k8s/security-monitoring/healthcheck-rbac.yaml"
  kubectl --context "$OS_CONTEXT" apply -f "$REPO_ROOT/k8s/security-monitoring/healthcheck-rbac.yaml"

  kubectl --context "$AWS_CONTEXT" apply -f "$REPO_ROOT/k8s/security-monitoring/healthcheck-cronjob.yaml"
  kubectl --context "$AWS_CONTEXT" -n spire set env cronjob/security-healthcheck \
    CLOUD_PROVIDER=aws \
    LOKI_PUSH_URL=http://loki.plg-stack.svc.cluster.local:3100/loki/api/v1/push

  # OpenStack promtail cũng dùng chung đường relay này (deploy-app.sh) vì
  # OpenStack không có Loki riêng — kế thừa cùng giới hạn: relay chạy trên
  # máy deployer, không phải cluster-native.
  kubectl --context "$OS_CONTEXT" apply -f "$REPO_ROOT/k8s/security-monitoring/healthcheck-cronjob.yaml"
  kubectl --context "$OS_CONTEXT" -n spire set env cronjob/security-healthcheck \
    CLOUD_PROVIDER=openstack \
    LOKI_PUSH_URL=http://172.10.10.1:13099/loki/api/v1/push

  log_info "Security control-plane health-check deployed (chạy mỗi 1 phút trên cả 2 cluster)"
}

verify_deployment() {
  log_step "6. Verify Deployment"

  log_info "Namespaces on AWS:"
  kubectl --context $AWS_CONTEXT get ns

  log_info ""
  log_info "Keycloak pods on AWS:"
  kubectl --context $AWS_CONTEXT get pods -n identity

  log_info ""
  log_info "SPIRE pods on AWS:"
  kubectl --context $AWS_CONTEXT get pods -n spire

  log_info ""
  log_info "SPIRE pods on OpenStack:"
  kubectl --context $OS_CONTEXT get pods -n spire

  log_info ""
  log_info "OPA pods on AWS:"
  kubectl --context $AWS_CONTEXT get pods -n financial

  log_info ""
  log_info "OPA pods on OpenStack (expected empty here; deployed later by os-security.yaml):"
  kubectl --context $OS_CONTEXT get pods -n financial

  log_info ""
  log_info "Envoy ConfigMaps on AWS:"
  kubectl --context $AWS_CONTEXT get cm -n financial

  log_info ""

  log_step "6.1 Readiness checks"
  check_rollout "$AWS_CONTEXT" "identity" "deployment" "keycloak" "${TIMEOUT_KEYCLOAK}s" "false"
  check_rollout "$AWS_CONTEXT" "spire" "deployment" "spire-server" "${TIMEOUT_WAIT}s" "true"
  check_daemonset_ready "$AWS_CONTEXT" "spire" "spire-agent" "true"
  check_rollout "$OS_CONTEXT" "spire" "deployment" "spire-server" "${TIMEOUT_WAIT}s" "true"
  check_daemonset_ready "$OS_CONTEXT" "spire" "spire-agent" "true"
  check_rollout "$AWS_CONTEXT" "financial" "deployment" "opa-server" "${TIMEOUT_WAIT}s" "true"
  # OS opa-server is deployed later by os-security.yaml (deploy-app.sh Step 5), not here.

  if [ "$VERIFY_FAILED" -ne 0 ]; then
    log_error "Security stack verification failed. Check pods/events/logs before continuing."
    exit 1
  fi

  log_info "✓ Security stack deployment verification completed"
}

main() {
  log_info "SPIRE / OPA / Envoy / Keycloak Deployment Script"
  log_info ""

  # Check prerequisites
  log_info "Checking prerequisites..."
  check_kctl_context $AWS_CONTEXT
  check_kctl_context $OS_CONTEXT

  # Deploy steps
  deploy_step_1_namespaces
  deploy_step_2_keycloak
  provision_spire_root_ca
  deploy_step_3_spire_aws
  deploy_step_3_spire_os
  register_spire_workloads
  deploy_step_4_opa
  deploy_security_healthcheck

  # Verify
  verify_deployment

  log_info ""
  log_info "================================"
  log_info "✓ All components deployed successfully!"
  log_info "================================"
  log_info ""
  log_info "Next steps:"
  if financial_manifests_ready; then
    log_info "1. Deploy financial workloads:"
    log_info "   kubectl --context ctx-aws apply -f k8s/financial/aws-services.yaml"
    log_info "   kubectl --context ctx-openstack apply -f k8s/financial/os-services.yaml"
    log_info "2. Deploy PLG stack: ./scripts/deploy-plg-stack.sh"
    log_info "3. Verify workloads: kubectl --context ctx-aws get pods -A && kubectl --context ctx-openstack get pods -A"
  else
    log_info "1. Financial manifests are not ready yet (k8s/financial/*.yaml still TODO/empty)."
    log_info "2. Populate financial manifests before running kubectl apply on k8s/financial/*.yaml."
    log_info "3. Deploy PLG stack after workloads are ready: ./scripts/deploy-plg-stack.sh"
  fi
  log_info ""
}

main "$@"
