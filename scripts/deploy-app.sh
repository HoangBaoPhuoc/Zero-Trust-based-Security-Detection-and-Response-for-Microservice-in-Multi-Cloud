#!/usr/bin/env bash
# Deploy the ZTLab application layer (K8s manifests) onto AWS and OpenStack K3s
# clusters that are already provisioned and running. For infra-from-zero
# (Terraform + Ansible + this script combined), use scripts/deploy-all.sh instead.
#
# This script intentionally orchestrates the existing focused scripts instead of
# replacing them:
#   - scripts/k8s-tunnel.sh for ctx-aws and ctx-openstack
#   - scripts/sync-financial-images.sh for local image import on all K3s nodes
#   - scripts/deploy-security-stack.sh for SPIRE, OPA, Envoy, and Keycloak
#
# Usage:
#   ./scripts/deploy-app.sh
#   ./scripts/deploy-app.sh --skip-images
#   ./scripts/deploy-app.sh --skip-tunnel
#   ./scripts/deploy-app.sh --skip-security-stack

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AWS_CONTEXT="${AWS_CONTEXT:-ctx-aws}"
OS_CONTEXT="${OS_CONTEXT:-ctx-openstack}"
AWS_KEY_PAIR_NAME="${AWS_KEY_PAIR_NAME:-ztlab-key}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/${AWS_KEY_PAIR_NAME}}"

SKIP_IMAGES=false
SKIP_TUNNEL=false
SKIP_SECURITY_STACK=false

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log()  { echo -e "${BLUE}[DEPLOY-ALL]${NC} $*"; }
ok()   { echo -e "${GREEN}[  OK  ]${NC} $*"; }
warn() { echo -e "${YELLOW}[ WARN ]${NC} $*"; }
fail() { echo -e "${RED}[ FAIL ]${NC} $*"; exit 1; }
step() {
  echo -e "\n${BLUE}══════════════════════════════════════════${NC}"
  echo -e "${BLUE} $*${NC}"
  echo -e "${BLUE}══════════════════════════════════════════${NC}"
}

usage() {
  cat <<EOF
Usage: $(basename "$0") [--skip-images] [--skip-tunnel] [--skip-security-stack]

Options:
  --skip-images          Do not rebuild/sync ztlab/* images to K3s nodes
  --skip-tunnel          Assume ctx-aws and ctx-openstack are already reachable
  --skip-security-stack  Skip SPIRE/OPA/Envoy/Keycloak deployment
  -h, --help             Show this help
EOF
}

for arg in "$@"; do
  case "$arg" in
    --skip-images) SKIP_IMAGES=true ;;
    --skip-tunnel) SKIP_TUNNEL=true ;;
    --skip-security-stack) SKIP_SECURITY_STACK=true ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      usage >&2
      fail "Unknown option: $arg"
      ;;
  esac
done

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "Missing required command: $1"
}

kaws() {
  kubectl --context "$AWS_CONTEXT" "$@"
}

kos() {
  kubectl --context "$OS_CONTEXT" "$@"
}

verify_context() {
  local ctx="$1"
  kubectl --context "$ctx" get nodes --request-timeout=10s >/dev/null 2>&1 \
    || fail "Cannot reach Kubernetes context: $ctx. Run ./scripts/k8s-tunnel.sh up all"
  ok "Connected to $ctx ($(kubectl --context "$ctx" get nodes --no-headers | wc -l | tr -d ' ') nodes)"
}

wait_deployment() {
  local ctx="$1"
  local ns="$2"
  local name="$3"
  local timeout="${4:-180s}"

  kubectl --context "$ctx" rollout status "deployment/$name" -n "$ns" --timeout="$timeout"
}

wait_daemonset() {
  local ctx="$1"
  local ns="$2"
  local name="$3"
  local timeout="${4:-180s}"

  kubectl --context "$ctx" rollout status "daemonset/$name" -n "$ns" --timeout="$timeout"
}

wait_statefulset() {
  local ctx="$1"
  local ns="$2"
  local name="$3"
  local timeout="${4:-240s}"

  kubectl --context "$ctx" rollout status "statefulset/$name" -n "$ns" --timeout="$timeout"
}

regenerate_policy_files() {
  step "Step 0b: Regenerate OPA/NetworkPolicy files from policy/service-graph.yaml"
  # Safety net for VIEC-CON-TON-DONG.md item 3: opa/policies/service_acl.rego
  # and k8s/financial/network-policies/{aws,os}-pod-segmentation.yaml are
  # GENERATED from policy/service-graph.yaml, committed to the repo as the
  # deployable artifact. If someone edits service-graph.yaml but forgets to
  # re-run the 2 generators before deploying, the cluster silently gets the
  # OLD policy instead (tests/test_service_graph_consistency.py only catches
  # this in CI/manually run, not automatically on deploy). Run both here,
  # before anything reads either output file, so that can no longer happen.
  # No-op (git-clean) when service-graph.yaml already matches committed output.
  python3 "$REPO_ROOT/scripts/gen-rego-acl.py"
  python3 "$REPO_ROOT/scripts/gen-networkpolicy.py"
  ok "Policy files regenerated from policy/service-graph.yaml"
}

apply_namespaces() {
  step "Step 1: Namespaces"
  kaws apply -f "$REPO_ROOT/k8s/namespaces.yaml"
  kos apply -f "$REPO_ROOT/k8s/namespaces.yaml"
  kaws apply -f "$REPO_ROOT/k8s/plg-stack/namespace.yaml"
  kos apply -f "$REPO_ROOT/k8s/plg-stack/namespace.yaml"
  ok "Namespaces ready on both clusters"
}

apply_network_policies() {
  step "Step 1b: Network policies (early — must exist before any pod with restricted egress starts)"
  kaws apply -f "$REPO_ROOT/k8s/financial/network-policies/aws-allow-list.yaml"
  kos apply -f "$REPO_ROOT/k8s/financial/network-policies/os-allow-list.yaml"
  ok "Network policies applied on both clusters"
}

deploy_gatekeeper() {
  step "Step 1c: OPA Gatekeeper (K8s admission control)"
  kaws apply -f "https://raw.githubusercontent.com/open-policy-agent/gatekeeper/v3.16.3/deploy/gatekeeper.yaml"
  kubectl --context "$AWS_CONTEXT" wait --for=condition=Ready pod -l control-plane=controller-manager -n gatekeeper-system --timeout=180s
  kubectl --context "$AWS_CONTEXT" wait --for=condition=Ready pod -l control-plane=audit-controller -n gatekeeper-system --timeout=180s
  kaws apply -f "$REPO_ROOT/k8s/gatekeeper/constraint-templates.yaml"
  sleep 5
  kaws apply -f "$REPO_ROOT/k8s/gatekeeper/constraints.yaml"
  ok "Gatekeeper installed with ConstraintTemplates/Constraints (nonroot=dryrun, image-policy=deny)"
}

deploy_istio() {
  step "Step 1d: Istio (service mesh — all financial services migrated, both clouds, STRICT mTLS)"
  local istio_version="1.22.3"
  local istioctl_bin="istioctl"
  if ! command -v istioctl >/dev/null 2>&1; then
    if [[ -x "$REPO_ROOT/.istio-${istio_version}/bin/istioctl" ]]; then
      istioctl_bin="$REPO_ROOT/.istio-${istio_version}/bin/istioctl"
    else
      log "istioctl not found — downloading pinned version $istio_version"
      (cd "$REPO_ROOT" && curl -sL https://istio.io/downloadIstio | ISTIO_VERSION="$istio_version" TARGET_ARCH=x86_64 sh -)
      mv "$REPO_ROOT/istio-${istio_version}" "$REPO_ROOT/.istio-${istio_version}"
      istioctl_bin="$REPO_ROOT/.istio-${istio_version}/bin/istioctl"
    fi
  fi

  # k8s/istio/istio-operator.yaml is the single source of truth for install
  # config: trustDomain MUST match SPIRE's (ztlab.local), not Istio's
  # cluster.local default — otherwise Istio's own inbound mTLS validation
  # context rejects SPIRE-issued peer certs with a CERTIFICATE_UNKNOWN TLS
  # alert (confirmed via repro). The opa-ext-authz extensionProvider
  # replicates the hand-rolled Envoy's ext_authz filter (fail-closed OPA
  # check) for every migrated service that needs real Rego enforcement, not
  # just a static ALLOW — see the CUSTOM AuthorizationPolicy entries in
  # k8s/financial/istio-policies.yaml. SPIRE stays the actual cert source via
  # the Workload API socket (sidecar.istio.io/userVolume annotations in
  # aws-services.yaml) — trustDomain here only has to match for Istio's own
  # validation logic to accept those certs, Istio's Citadel CA is never
  # actually used.
  # Installed on BOTH clusters — core-banking/account-service/
  # transaction-service (OpenStack) are migrated too, and the cross-cloud
  # payment-service→core-banking call needs a real Istio sidecar on the
  # OpenStack side to present/validate SPIRE certs via ISTIO_MUTUAL.
  # extensionProviders.opa-ext-authz resolves per-cluster to each cluster's
  # own local opa-service — no cross-cluster wiring needed.
  "$istioctl_bin" install --context "$AWS_CONTEXT" -f "$REPO_ROOT/k8s/istio/istio-operator.yaml" -y
  "$istioctl_bin" install --context "$OS_CONTEXT" -f "$REPO_ROOT/k8s/istio/istio-operator.yaml" -y

  kubectl --context "$AWS_CONTEXT" wait --for=condition=Ready pod -l app=istiod -n istio-system --timeout=180s
  kubectl --context "$OS_CONTEXT" wait --for=condition=Ready pod -l app=istiod -n istio-system --timeout=180s

  # istio-injection=enabled gates the whole namespace. All 8 financial
  # services are migrated now, so nothing needs the opt-out annotation
  # anymore — kept as a no-op comment in case a future service is added
  # un-migrated: give it sidecar.istio.io/inject: "false" or it will be
  # auto-injected and likely break (no SPIRE workload-socket volume mount).
  kaws label namespace financial istio-injection=enabled --overwrite
  kos label namespace financial istio-injection=enabled --overwrite
  ok "Istio installed on both clouds (trustDomain=ztlab.local), financial namespaces labeled for injection"
}

sync_images() {
  step "Step 2: Images"
  if [[ "$SKIP_IMAGES" == true ]]; then
    log "Skipping image build/sync"
    return
  fi

  "$REPO_ROOT/scripts/sync-financial-images.sh"
  ok "Images synced to AWS and OpenStack K3s nodes"
}

deploy_security_stack() {
  step "Step 3: Security stack"
  if [[ "$SKIP_SECURITY_STACK" == true ]]; then
    log "Skipping security stack"
    return
  fi

  "$REPO_ROOT/scripts/deploy-security-stack.sh"
  ok "Security stack deployed"
}

deploy_openldap_and_federation() {
  step "Step 3b: OpenLDAP (SCIM demo directory) + Keycloak User Federation"
  if [[ "$SKIP_SECURITY_STACK" == true ]]; then
    log "Skipping OpenLDAP federation (security stack was skipped, Keycloak not available)"
    return
  fi

  kaws apply -f "$REPO_ROOT/k8s/identity/openldap.yaml"
  kubectl --context "$AWS_CONTEXT" wait --for=condition=Ready pod -l app=openldap -n identity-directory --timeout=90s
  kaws apply -f "$REPO_ROOT/k8s/identity/openldap-seed-job.yaml"
  kubectl --context "$AWS_CONTEXT" wait --for=condition=complete job/openldap-seed -n identity-directory --timeout=60s || true

  local admin_pass
  admin_pass="$(kaws get secret keycloak-secret -n identity -o jsonpath='{.data.admin-password}' | base64 -d)"

  # Component idempotency: realm-config.json also declares this LDAP provider
  # for a FRESH Keycloak import, but Keycloak's --import-realm only runs on
  # first boot of a realm — it will not retrofit this component onto an
  # already-imported realm. Register it live via Admin API too so it exists
  # even when Keycloak itself wasn't redeployed this run.
  kaws delete pod kc-ldap-federation-setup -n identity --ignore-not-found --wait=true >/dev/null 2>&1 || true
  kaws run kc-ldap-federation-setup --image=python:3.12-alpine -n identity --restart=Never --command -- sh -c "sleep 60" >/dev/null 2>&1 || true
  kubectl --context "$AWS_CONTEXT" wait --for=condition=Ready pod/kc-ldap-federation-setup -n identity --timeout=60s >/dev/null 2>&1 || true
  kubectl --context "$AWS_CONTEXT" exec -n identity kc-ldap-federation-setup -- python3 -c "
import urllib.request, json, urllib.parse, urllib.error

tok_data = urllib.parse.urlencode({'grant_type':'password','client_id':'admin-cli','username':'admin','password':'$admin_pass'}).encode()
req = urllib.request.Request('http://keycloak.identity.svc.cluster.local:8080/realms/master/protocol/openid-connect/token', data=tok_data)
token = json.load(urllib.request.urlopen(req))['access_token']

req = urllib.request.Request('http://keycloak.identity.svc.cluster.local:8080/admin/realms/ztlab/components', headers={'Authorization': 'Bearer ' + token})
comps = json.load(urllib.request.urlopen(req))
if any(c.get('name') == 'ldap-directory' and c.get('providerId') == 'ldap' for c in comps):
    print('ldap-directory component already registered, skipping')
else:
    payload = {
        'name': 'ldap-directory', 'providerId': 'ldap',
        'providerType': 'org.keycloak.storage.UserStorageProvider', 'parentId': 'ztlab',
        'config': {
            'enabled': ['true'], 'priority': ['0'], 'editMode': ['READ_ONLY'],
            'syncRegistrations': ['false'], 'vendor': ['other'],
            'usernameLDAPAttribute': ['uid'], 'rdnLDAPAttribute': ['uid'],
            'uuidLDAPAttribute': ['entryUUID'],
            'userObjectClasses': ['inetOrgPerson, organizationalPerson'],
            'connectionUrl': ['ldap://openldap.identity-directory.svc.cluster.local:389'],
            'usersDn': ['ou=people,dc=ztlab,dc=local'], 'authType': ['simple'],
            'bindDn': ['cn=admin,dc=ztlab,dc=local'], 'bindCredential': ['ztlab-ldap-admin-2026'],
            'searchScope': ['1'], 'trustEmail': ['true'], 'useTruststoreSpi': ['never'],
            'connectionPooling': ['true'], 'pagination': ['true'],
            'batchSizeForSync': ['1000'], 'fullSyncPeriod': ['-1'], 'changedSyncPeriod': ['-1'],
            'importEnabled': ['true'],
        }
    }
    req = urllib.request.Request('http://keycloak.identity.svc.cluster.local:8080/admin/realms/ztlab/components', data=json.dumps(payload).encode(), headers={'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'}, method='POST')
    urllib.request.urlopen(req)
    print('ldap-directory component created')
" || warn "OpenLDAP Keycloak federation setup failed (non-fatal — demo/illustration component)"
  kubectl --context "$AWS_CONTEXT" delete pod kc-ldap-federation-setup -n identity --ignore-not-found --wait=false >/dev/null 2>&1 || true

  ok "OpenLDAP deployed, seeded, and registered as Keycloak User Federation (READ_ONLY, demo directory — not a real corporate LDAP)"
}

deploy_audience_mapper() {
  step "Step 3b2: Keycloak Audience protocol mapper (web-portal/api-gateway -> aud=api-gateway)"
  if [[ "$SKIP_SECURITY_STACK" == true ]]; then
    log "Skipping Audience mapper (security stack was skipped, Keycloak not available)"
    return
  fi

  local admin_pass
  admin_pass="$(kaws get secret keycloak-secret -n identity -o jsonpath='{.data.admin-password}' | base64 -d)"

  # Same idempotency caveat as deploy_openldap_and_federation: realm-config.json
  # now declares this mapper for a FRESH import, but --import-realm won't
  # retrofit it onto an already-imported realm (T-1.4 regression, 2026-09-05:
  # this exact mapper was added by hand via Admin API in a previous session,
  # then silently lost on the next from-scratch deploy-all.sh because it lived
  # nowhere else). Register it live too so every deploy ends up with it.
  kaws delete pod kc-audience-mapper-setup -n identity --ignore-not-found --wait=true >/dev/null 2>&1 || true
  kaws run kc-audience-mapper-setup --image=python:3.12-alpine -n identity --restart=Never --command -- sh -c "sleep 60" >/dev/null 2>&1 || true
  kubectl --context "$AWS_CONTEXT" wait --for=condition=Ready pod/kc-audience-mapper-setup -n identity --timeout=60s >/dev/null 2>&1 || true
  kubectl --context "$AWS_CONTEXT" exec -n identity kc-audience-mapper-setup -- python3 -c "
import urllib.request, json, urllib.parse

tok_data = urllib.parse.urlencode({'grant_type':'password','client_id':'admin-cli','username':'admin','password':'$admin_pass'}).encode()
req = urllib.request.Request('http://keycloak.identity.svc.cluster.local:8080/realms/master/protocol/openid-connect/token', data=tok_data)
token = json.load(urllib.request.urlopen(req))['access_token']
headers = {'Authorization': 'Bearer ' + token}

for client_id in ('api-gateway', 'web-portal'):
    req = urllib.request.Request('http://keycloak.identity.svc.cluster.local:8080/admin/realms/ztlab/clients?clientId=' + client_id, headers=headers)
    clients = json.load(urllib.request.urlopen(req))
    if not clients:
        print(client_id, '-> client not found, skipping')
        continue
    internal_id = clients[0]['id']

    req = urllib.request.Request('http://keycloak.identity.svc.cluster.local:8080/admin/realms/ztlab/clients/' + internal_id + '/protocol-mappers/models', headers=headers)
    mappers = json.load(urllib.request.urlopen(req))
    if any(m.get('name') == 'aud-api-gateway' for m in mappers):
        print(client_id, '-> aud-api-gateway mapper already present, skipping')
        continue

    payload = {
        'name': 'aud-api-gateway', 'protocol': 'openid-connect',
        'protocolMapper': 'oidc-audience-mapper', 'consentRequired': False,
        'config': {'included.client.audience': 'api-gateway', 'id.token.claim': 'false', 'access.token.claim': 'true'},
    }
    req = urllib.request.Request(
        'http://keycloak.identity.svc.cluster.local:8080/admin/realms/ztlab/clients/' + internal_id + '/protocol-mappers/models',
        data=json.dumps(payload).encode(), headers={**headers, 'Content-Type': 'application/json'}, method='POST')
    urllib.request.urlopen(req)
    print(client_id, '-> aud-api-gateway mapper created')
" || warn "Keycloak Audience mapper setup failed (non-fatal — but T-1.4 audience check degrades to a no-op without it, see KET-QUA-KIEM-TRA.md)"
  kubectl --context "$AWS_CONTEXT" delete pod kc-audience-mapper-setup -n identity --ignore-not-found --wait=false >/dev/null 2>&1 || true

  ok "Keycloak Audience mapper ensured on web-portal + api-gateway clients"
}

deploy_stepup_flow() {
  step "Step 3b3: Keycloak browser-stepup authentication flow (T-4.2 step-up OTP)"
  if [[ "$SKIP_SECURITY_STACK" == true ]]; then
    log "Skipping browser-stepup flow (security stack was skipped, Keycloak not available)"
    return
  fi

  local admin_pass
  admin_pass="$(kaws get secret keycloak-secret -n identity -o jsonpath='{.data.admin-password}' | base64 -d)"

  # Same idempotency caveat as deploy_audience_mapper/deploy_openldap_and_federation:
  # client "web-portal-stepup" comes from realm-config.json on fresh --import-realm,
  # but the authentication flow it needs to bind to does NOT — it was hand-built via
  # Admin API in a prior session and lost on the next from-scratch deploy (see
  # VIEC-CON-TON-DONG.md item 1). Register it live too so every deploy ends up with it.
  kaws delete pod kc-stepup-flow-setup -n identity --ignore-not-found --wait=true >/dev/null 2>&1 || true
  kaws run kc-stepup-flow-setup --image=python:3.12-alpine -n identity --restart=Never --command -- sh -c "sleep 60" >/dev/null 2>&1 || true
  kubectl --context "$AWS_CONTEXT" wait --for=condition=Ready pod/kc-stepup-flow-setup -n identity --timeout=60s >/dev/null 2>&1 || true
  kubectl --context "$AWS_CONTEXT" exec -n identity kc-stepup-flow-setup -- python3 -c "
import urllib.request, json, urllib.parse

KC = 'http://keycloak.identity.svc.cluster.local:8080'
REALM = 'ztlab'

def call(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(KC + path, data=data, headers=headers, method=method)
    if data is not None:
        req.add_header('Content-Type', 'application/json')
    try:
        resp = urllib.request.urlopen(req)
        raw = resp.read()
        return json.loads(raw) if raw else None
    except urllib.error.HTTPError as e:
        raise RuntimeError(f'{method} {path} -> {e.code}: {e.read().decode()}')

tok_data = urllib.parse.urlencode({'grant_type':'password','client_id':'admin-cli','username':'admin','password':'$admin_pass'}).encode()
token = json.load(urllib.request.urlopen(urllib.request.Request(KC + '/realms/master/protocol/openid-connect/token', data=tok_data)))['access_token']
headers = {'Authorization': 'Bearer ' + token}

flows = call('GET', f'/admin/realms/{REALM}/authentication/flows')
if any(f['alias'] == 'browser-stepup' for f in flows):
    print('browser-stepup flow already exists, skipping creation')
else:
    # 1. Copy built-in 'browser' -> 'browser-stepup' (brings 'browser-stepup forms'
    #    and its nested Conditional-OTP subflow along for free).
    call('POST', f'/admin/realms/{REALM}/authentication/flows/browser/copy', {'newName': 'browser-stepup'})

    # 2. Add a new CONDITIONAL subflow 'Stepup-2fa' as a child of 'browser-stepup
    #    forms' (NOT of 'browser-stepup' itself, or it lands at the wrong level).
    call('POST', f'/admin/realms/{REALM}/authentication/flows/browser-stepup%20forms/executions/flow',
         {'name': 'Stepup-2fa', 'description': 'Step-up: OTP khi LoA >= 2 (acr=high)', 'provider': 'basic-flow', 'type': 'basic-flow'})

    execs = call('GET', f'/admin/realms/{REALM}/authentication/flows/browser-stepup/executions')
    stepup_exec = next(e for e in execs if e.get('level') == 1 and e.get('authenticationFlow') and e.get('description', '').startswith('Step-up:'))
    flow_id = stepup_exec['flowId']

    # QUIRK (found 2026-09-08, re-derived from scratch after infra destroy): the
    # 'executions/flow' endpoint's JSON body field is 'name' per the docs, but on
    # this Keycloak 24.0.3 it does NOT set the resulting flow's alias — the new
    # flow comes back with alias=null, so every subsequent by-alias lookup
    # ('/authentication/flows/Stepup-2fa/...') 400s with 'Parent flow doesn't
    # exist'. Fix: PUT the flow object directly with the alias set explicitly.
    call('PUT', f'/admin/realms/{REALM}/authentication/flows/{flow_id}',
         {'id': flow_id, 'alias': 'Stepup-2fa', 'description': 'Step-up: OTP khi LoA >= 2 (acr=high)',
          'providerId': 'basic-flow', 'topLevel': False, 'builtIn': False})

    # 3. Flip the subflow execution from DISABLED -> CONDITIONAL.
    call('PUT', f'/admin/realms/{REALM}/authentication/flows/browser-stepup%20forms/executions',
         {'id': stepup_exec['id'], 'requirement': 'CONDITIONAL'})

    # 4. Add the 2 child executions inside 'Stepup-2fa' and require both.
    call('POST', f'/admin/realms/{REALM}/authentication/flows/Stepup-2fa/executions/execution', {'provider': 'conditional-level-of-authentication'})
    call('POST', f'/admin/realms/{REALM}/authentication/flows/Stepup-2fa/executions/execution', {'provider': 'auth-otp-form'})
    child_execs = call('GET', f'/admin/realms/{REALM}/authentication/flows/Stepup-2fa/executions')
    cond_exec = next(e for e in child_execs if e['providerId'] == 'conditional-level-of-authentication')
    otp_exec = next(e for e in child_execs if e['providerId'] == 'auth-otp-form')
    call('PUT', f'/admin/realms/{REALM}/authentication/flows/Stepup-2fa/executions', {'id': cond_exec['id'], 'requirement': 'REQUIRED'})
    call('PUT', f'/admin/realms/{REALM}/authentication/flows/Stepup-2fa/executions', {'id': otp_exec['id'], 'requirement': 'REQUIRED'})

    # 5. Configure the LoA condition: acr=high (level 2), 10h cached max-age.
    #    Key names MUST be 'loa-condition-level'/'loa-max-age' — the UI helpText
    #    names ('level'/'maxAge') are silently ignored, LoA check never fires.
    call('POST', f'/admin/realms/{REALM}/authentication/executions/{cond_exec[\"id\"]}/config',
         {'alias': 'stepup-loa-2', 'config': {'loa-condition-level': '2', 'loa-max-age': '36000'}})

    print('browser-stepup flow created')

# 6. Bind 'browser-stepup' as the browser flow of client 'web-portal-stepup' ONLY.
#    Do NOT bind it on 'web-portal' — that forces OTP on every normal login (regression
#    seen once already, see KET-QUA-KIEM-TRA.md).
browser_stepup_id = next(f['id'] for f in call('GET', f'/admin/realms/{REALM}/authentication/flows') if f['alias'] == 'browser-stepup')
clients = call('GET', f'/admin/realms/{REALM}/clients?clientId=web-portal-stepup')
if not clients:
    print('web-portal-stepup client not found, skipping flow binding')
else:
    client_id = clients[0]['id']
    overrides = clients[0].get('authenticationFlowBindingOverrides', {})
    if overrides.get('browser') == browser_stepup_id:
        print('web-portal-stepup already bound to browser-stepup, skipping')
    else:
        overrides['browser'] = browser_stepup_id
        call('PUT', f'/admin/realms/{REALM}/clients/{client_id}', {'authenticationFlowBindingOverrides': overrides})
        print('web-portal-stepup bound to browser-stepup')

# 7. Ensure the demo user exists with CONFIGURE_TOTP pending. This only creates
# the account/required-action — it deliberately does NOT fabricate an OTP
# secret (secretData must come from a real QR enrollment via the browser; a
# hand-rolled secret was tried before and is not a faithful demo — see
# VIEC-CON-TON-DONG.md item 1). Finish enrollment once, interactively, via
# \$KC_URL/realms/ztlab/account, then the credential persists across redeploys
# (it lives in Postgres, not in this script).
users = call('GET', f'/admin/realms/{REALM}/users?username=stepup-demo&exact=true')
if users:
    print('stepup-demo user already exists, skipping')
else:
    call('POST', f'/admin/realms/{REALM}/users',
         {'username': 'stepup-demo', 'enabled': True, 'requiredActions': ['CONFIGURE_TOTP'],
          'credentials': [{'type': 'password', 'value': 'StepupDemo123!', 'temporary': False}]})
    print('stepup-demo user created (requiredActions=CONFIGURE_TOTP, needs one interactive login to enroll real OTP)')
" || warn "Keycloak browser-stepup flow setup failed (non-fatal — but T-4.2 step-up OTP degrades to no-op without it, see VIEC-CON-TON-DONG.md item 1)"
  kubectl --context "$AWS_CONTEXT" delete pod kc-stepup-flow-setup -n identity --ignore-not-found --wait=false >/dev/null 2>&1 || true

  ok "Keycloak browser-stepup flow ensured, bound to web-portal-stepup client"
}

deploy_aws_saml_federation() {
  step "Step 3c: AWS IAM SAML federation (AWS Console SSO via Keycloak)"
  if [[ "$SKIP_SECURITY_STACK" == true ]]; then
    log "Skipping AWS SAML federation (security stack was skipped, Keycloak not available)"
    return
  fi
  if ! command -v terraform >/dev/null 2>&1; then
    warn "terraform not found — skipping AWS SAML federation (non-fatal, admin-console-SSO convenience only)"
    return
  fi
  if ! aws sts get-caller-identity >/dev/null 2>&1; then
    warn "No AWS credentials in environment (see DEPLOY.md Step 2: export \$(grep -v '^#' .env | xargs)) — skipping AWS SAML federation"
    return
  fi

  local meta_file="/tmp/ztlab-keycloak-saml-metadata-$$.xml"
  # kubectl run --rm's own "pod ... deleted" status line can land on stdout
  # and corrupt a captured file — use a plain pod + exec + explicit delete
  # instead of --rm to keep the captured metadata byte-exact.
  kaws delete pod kc-saml-meta -n identity --ignore-not-found --wait=true >/dev/null 2>&1 || true
  kaws run kc-saml-meta --image=curlimages/curl -n identity --restart=Never --command -- sh -c "sleep 30" >/dev/null
  kubectl --context "$AWS_CONTEXT" wait --for=condition=Ready pod/kc-saml-meta -n identity --timeout=30s >/dev/null
  kubectl --context "$AWS_CONTEXT" exec -n identity kc-saml-meta -- curl -s http://keycloak.identity.svc.cluster.local:8080/realms/ztlab/protocol/saml/descriptor > "$meta_file" || true
  kaws delete pod kc-saml-meta -n identity --ignore-not-found --wait=false >/dev/null 2>&1 || true

  if ! python3 -c "import xml.dom.minidom; xml.dom.minidom.parse('$meta_file')" 2>/dev/null; then
    warn "Keycloak SAML metadata unreachable or invalid (is Keycloak Running? check: kubectl --context $AWS_CONTEXT get pods -n identity) — skipping AWS SAML federation, non-fatal"
    rm -f "$meta_file"
    return
  fi

  (cd "$REPO_ROOT/terraform/aws" && terraform apply -auto-approve \
    -var="keycloak_saml_metadata_path=$meta_file" \
    -target=aws_iam_saml_provider.keycloak \
    -target=aws_iam_role.ztlab_sso_admin \
    -target=aws_iam_role_policy_attachment.ztlab_sso_admin_readonly) \
    && ok "AWS IAM SAML provider + ztlab-sso-admin role applied" \
    || warn "AWS SAML federation terraform apply failed (non-fatal — admin-console-SSO convenience only)"

  rm -f "$meta_file"
}

deploy_financial_infra() {
  step "Step 4: Financial infrastructure"

  # Shared ConfigMap (financial-common-config) — both clusters need it
  kaws apply -f "$REPO_ROOT/k8s/financial/services.yaml"
  kos apply -f "$REPO_ROOT/k8s/financial/services.yaml"

  # Redis: AWS only (fraud-detection velocity cache + IP block list)
  kaws apply -f "$REPO_ROOT/k8s/financial/redis.yaml"
  wait_deployment "$AWS_CONTEXT" financial redis 120s

  # Postgres: OpenStack only (account-service + transaction-service)
  kos apply -f "$REPO_ROOT/k8s/financial/postgres-accounts.yaml"
  kos apply -f "$REPO_ROOT/k8s/financial/postgres-txn.yaml"
  wait_deployment "$OS_CONTEXT" financial postgres-accounts 180s
  wait_deployment "$OS_CONTEXT" financial postgres-txn 180s

  # pgAdmin → OpenStack (cùng cluster với Postgres, svc.cluster.local resolve được)
  # RedisInsight → AWS (cùng cluster với Redis)
  kos apply -f "$REPO_ROOT/k8s/financial/db-admin-ui.yaml"
  kaws apply -f "$REPO_ROOT/k8s/financial/db-admin-ui.yaml"

  ok "Redis on AWS, Postgres on OpenStack, DB admin UIs — ready"
}

deploy_financial_services() {
  step "Step 5: Financial workloads"

  create_financial_runtime_secrets
  create_core_banking_integrity_secret

  # OpenStack: OPA + Envoy configmaps must exist before os-services.yaml pods start
  kos apply -f "$REPO_ROOT/k8s/financial/os-security.yaml"

  # Always re-verify/re-create SPIRE registration entries, even when
  # --skip-security-stack is passed: SPIRE's datastore has no automatic
  # backup and has been observed to silently lose all entries on a
  # spire-server pod recreation, which otherwise doesn't surface until some
  # later pod restart fails istio-proxy's SDS handshake with a confusing,
  # seemingly-unrelated error. Cheap and idempotent when nothing is wrong.
  AWS_CONTEXT="$AWS_CONTEXT" OS_CONTEXT="$OS_CONTEXT" "$REPO_ROOT/scripts/ensure-spire-entries.sh"

  # patch-api-gateway and patch-web-portal must exist before pods are scheduled
  kaws create configmap patch-api-gateway \
    --from-file=main.py="$REPO_ROOT/services/api-gateway/main.py" \
    -n financial --dry-run=client -o yaml | kaws apply -f -
  kaws create configmap patch-web-portal \
    --from-file=main.py="$REPO_ROOT/services/web-portal/main.py" \
    -n financial --dry-run=client -o yaml | kaws apply -f -
  kaws create configmap patch-payment-service \
    --from-file=main.py="$REPO_ROOT/services/payment-service/main.py" \
    -n financial --dry-run=client -o yaml | kaws apply -f -
  # shared/posture.py (device posture self-check) isn't baked into any
  # service's image the way this patch mechanism was originally set up for
  # just main.py — mount it the same way so future edits here also take
  # effect on redeploy without an image rebuild.
  kaws create configmap patch-shared \
    --from-file=posture.py="$REPO_ROOT/shared/posture.py" \
    -n financial --dry-run=client -o yaml | kaws apply -f -
  # Templates aren't baked into the image at build time in a way this patch
  # mechanism previously covered — mount the whole templates/ dir the same
  # way grafana-dashboards mounts a directory of files (one ConfigMap key
  # per file, no subPath), so template-only changes also take effect on
  # redeploy without an image rebuild.
  kaws create configmap patch-web-portal-templates \
    --from-file="$REPO_ROOT/services/web-portal/templates" \
    -n financial --dry-run=client -o yaml | kaws apply -f -
  # Real attack-surface numbers (tests/generate_attack_surface_graph.py output)
  # for monitor.html's topology card — regenerate this file and re-run this
  # step whenever network policies/OPA paths change, so the figure shown in
  # the UI never drifts from what's actually enforced.
  if [ -f "$REPO_ROOT/results/attack_surface_graph.md" ]; then
    kaws create configmap attack-surface-graph \
      --from-file=attack_surface_graph.md="$REPO_ROOT/results/attack_surface_graph.md" \
      -n financial --dry-run=client -o yaml | kaws apply -f -
  fi

  # AWS: ingress-facing + fraud + notification + web portal
  kaws apply -f "$REPO_ROOT/k8s/financial/aws-services.yaml"
  kaws apply -f "$REPO_ROOT/k8s/financial/web-portal.yaml"
  for svc in api-gateway payment-service fraud-detection notification-service web-portal; do
    wait_deployment "$AWS_CONTEXT" financial "$svc" 180s
  done

  # OpenStack: core banking backend (requires os-security.yaml applied above)
  kos apply -f "$REPO_ROOT/k8s/financial/os-services.yaml"
  for svc in core-banking account-service transaction-service; do
    wait_deployment "$OS_CONTEXT" financial "$svc" 180s
  done

  # Device posture audit CronJob — same manifest on both clouds, RBAC scoped
  # to its own namespace only.
  kaws apply -f "$REPO_ROOT/k8s/financial/posture-agent-cronjob.yaml"
  kos apply -f "$REPO_ROOT/k8s/financial/posture-agent-cronjob.yaml"

  # Istio mesh policies (PeerAuthentication STRICT + per-workload PERMISSIVE
  # overrides for api-gateway/web-portal's public Traefik ingress,
  # DestinationRule custom-SAN overrides, CUSTOM AuthorizationPolicy → OPA)
  # — same file applied to both clusters; selectors simply don't match on
  # whichever cluster a given workload doesn't run on. Applied after all
  # financial Deployments exist on both clouds so every AuthorizationPolicy/
  # DestinationRule selector has something to match.
  kaws apply -f "$REPO_ROOT/k8s/financial/istio-policies.yaml"
  kos apply -f "$REPO_ROOT/k8s/financial/istio-policies.yaml"

  ok "AWS services, web portal, and OpenStack core banking ready"
}

keycloak_admin_password() {
  if [[ -n "${KEYCLOAK_ADMIN_PASSWORD:-}" ]]; then
    printf '%s' "$KEYCLOAK_ADMIN_PASSWORD"
    return
  fi

  local encoded
  encoded="$(kaws -n identity get secret keycloak-secret -o jsonpath='{.data.admin-password}' 2>/dev/null || true)"
  if [[ -n "$encoded" ]]; then
    printf '%s' "$encoded" | base64 -d
    return
  fi

  fail "KEYCLOAK_ADMIN_PASSWORD is unset and identity/keycloak-secret does not exist"
}

create_keycloak_admin_secret() {
  if kaws get secret keycloak-admin-secret -n plg-stack >/dev/null 2>&1; then
    log "keycloak-admin-secret already exists"
    return
  fi
  local admin_password
  admin_password="$(keycloak_admin_password)"
  kaws create secret generic keycloak-admin-secret -n plg-stack \
    --from-literal=password="$admin_password"
  ok "keycloak-admin-secret created"
}

create_ai_secret() {
  if kaws get secret ai-secrets -n plg-stack >/dev/null 2>&1; then
    log "ai-secrets already exists"
    return
  fi

  kaws create secret generic ai-secrets -n plg-stack \
    --from-literal=SOAR_DRY_RUN="${SOAR_DRY_RUN:-true}" \
    --from-literal=SOAR_AUTO_EXECUTE="${SOAR_AUTO_EXECUTE:-true}" \
    --from-literal=SOAR_MIN_SEVERITY="medium" \
    --from-literal=SOAR_MIN_CONFIDENCE="0.50" \
    --from-literal=SOAR_NAMESPACE="financial" \
    --from-literal=SOAR_ALLOWED_CONTEXTS="${SOAR_ALLOWED_CONTEXTS:-ctx-aws,ctx-openstack}" \
    --from-literal=SOAR_API_TOKEN="${SOAR_API_TOKEN:-}" \
    --from-literal=SOAR_CASE_STORE_PATH="/data/cases.jsonl" \
    --from-literal=PORTAL_URL="${PORTAL_URL:-http://portal.ztlab.local}" \
    --from-literal=ADMIN_WEBHOOK_URL="${ADMIN_WEBHOOK_URL:-}"
}

create_soar_main_patch_configmap() {
  # k8s/plg-stack/ai-soar.yaml mounts this ConfigMap over /app/main.py — the base
  # ztlab/soar-engine image lags services/soar-engine/main.py, so this patch is a
  # hard requirement (not optional), refreshed on every deploy.
  kaws create configmap soar-main-patch -n plg-stack \
    --from-file=main.py="$REPO_ROOT/services/soar-engine/main.py" \
    --dry-run=client -o yaml | kaws apply -f -
}

create_soar_openstack_kubeconfig_secret() {
  # k8s/plg-stack/ai-soar.yaml mounts this as /etc/soar/openstack-kubeconfig/kubeconfig;
  # soar-engine's isolate_workload/restrict_egress playbooks load it for context
  # "ctx-openstack" to act on the OpenStack cluster. Skip if already created for
  # this cluster generation — recreate manually (kubectl delete secret ...) if the
  # OpenStack k3s master was rebuilt without a full destroy-all cycle.
  if kaws get secret soar-openstack-kubeconfig -n plg-stack >/dev/null 2>&1; then
    log "soar-openstack-kubeconfig already exists"
    return
  fi

  local os_gateway_ip os_master_ip tmp_raw tmp_rewritten
  os_gateway_ip="$(ansible-inventory -i "$REPO_ROOT/ansible/inventory/hosts.yml" --host os_gateway | python3 -c 'import json,sys; print(json.load(sys.stdin)["ansible_host"])')"
  os_master_ip="$(ansible-inventory -i "$REPO_ROOT/ansible/inventory/hosts.yml" --host os_k3s_master | python3 -c 'import json,sys; print(json.load(sys.stdin)["ansible_host"])')"
  [[ -n "$os_gateway_ip" && -n "$os_master_ip" ]] || fail "Could not resolve os_gateway/os_k3s_master from inventory"

  tmp_raw="$(mktemp)"
  tmp_rewritten="$(mktemp)"
  ssh -i "$SSH_KEY" -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no \
      -o ProxyCommand="ssh -i ${SSH_KEY} -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -W %h:%p ubuntu@${os_gateway_ip}" \
      "ubuntu@${os_master_ip}" "sudo cat /etc/rancher/k3s/k3s.yaml" > "$tmp_raw"

  # Rewrite server from the node-local https://127.0.0.1:6443 to the private IP
  # reachable from AWS pods over the WireGuard tunnel, and rename default -> ctx-openstack
  # (soar-engine's _load_k8s() looks up the kubeconfig by that context name).
  python3 - "$tmp_raw" "$tmp_rewritten" "$os_master_ip" <<'PYEOF'
import sys, yaml
src, dst, master_ip = sys.argv[1:4]
with open(src) as f:
    kc = yaml.safe_load(f)
kc["clusters"][0]["name"] = "ctx-openstack"
kc["clusters"][0]["cluster"]["server"] = f"https://{master_ip}:6443"
kc["contexts"][0]["name"] = "ctx-openstack"
kc["contexts"][0]["context"]["cluster"] = "ctx-openstack"
kc["contexts"][0]["context"]["user"] = "ctx-openstack"
kc["users"][0]["name"] = "ctx-openstack"
kc["current-context"] = "ctx-openstack"
with open(dst, "w") as f:
    yaml.safe_dump(kc, f)
PYEOF

  kaws create secret generic soar-openstack-kubeconfig -n plg-stack \
    --from-file=kubeconfig="$tmp_rewritten"
  rm -f "$tmp_raw" "$tmp_rewritten"
  ok "soar-openstack-kubeconfig created"
}

create_smtp_secret() {
  if kaws get secret grafana-smtp-secret -n plg-stack >/dev/null 2>&1; then
    log "grafana-smtp-secret already exists"
    return
  fi
  # SMTP_PASS may be empty in lab — secret is created anyway so pods start cleanly.
  # soar-engine references this secret with optional: true.
  kaws create secret generic grafana-smtp-secret -n plg-stack \
    --from-literal=password="${SMTP_PASS:-}"
  ok "grafana-smtp-secret created"
}

deploy_vault_and_seed_secrets() {
  log "Deploying Vault and seeding grafana-smtp-secret KV"
  kaws apply -f "$REPO_ROOT/k8s/vault/vault.yaml"
  kubectl --context "$AWS_CONTEXT" wait --for=condition=Ready pod/vault-0 -n vault --timeout=120s

  local vault_status initialized sealed unseal_key root_token init_json

  vault_status="$(kaws exec -n vault vault-0 -- sh -c 'VAULT_ADDR=http://127.0.0.1:8200 vault status -format=json' 2>/dev/null || true)"
  initialized="$(echo "$vault_status" | python3 -c 'import json,sys
try:
    print(json.load(sys.stdin).get("initialized", False))
except Exception:
    print(False)' 2>/dev/null || echo False)"

  if [[ "$initialized" != "True" ]]; then
    log "Vault not initialized — running operator init (1 key share, lab-grade)"
    init_json="$(kaws exec -n vault vault-0 -- sh -c 'VAULT_ADDR=http://127.0.0.1:8200 vault operator init -key-shares=1 -key-threshold=1 -format=json')"
    unseal_key="$(echo "$init_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["unseal_keys_b64"][0])')"
    root_token="$(echo "$init_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["root_token"])')"
    kaws create secret generic vault-unseal-keys -n vault \
      --from-literal=unseal-key="$unseal_key" \
      --from-literal=root-token="$root_token" \
      --dry-run=client -o yaml | kaws apply -f -
  else
    log "Vault already initialized — reusing unseal key/root token from vault-unseal-keys secret"
    unseal_key="$(kaws get secret vault-unseal-keys -n vault -o jsonpath='{.data.unseal-key}' | base64 -d)"
    root_token="$(kaws get secret vault-unseal-keys -n vault -o jsonpath='{.data.root-token}' | base64 -d)"
  fi

  vault_status="$(kaws exec -n vault vault-0 -- sh -c 'VAULT_ADDR=http://127.0.0.1:8200 vault status -format=json' 2>/dev/null || true)"
  sealed="$(echo "$vault_status" | python3 -c 'import json,sys
try:
    print(json.load(sys.stdin).get("sealed", True))
except Exception:
    print(True)' 2>/dev/null || echo True)"
  if [[ "$sealed" != "False" ]]; then
    log "Unsealing Vault"
    kaws exec -n vault vault-0 -- sh -c "VAULT_ADDR=http://127.0.0.1:8200 vault operator unseal '$unseal_key'" >/dev/null
  fi

  kaws exec -n vault vault-0 -- sh -c "VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN='$root_token' vault secrets enable -path=secret kv-v2" >/dev/null 2>&1 || true
  kaws exec -n vault vault-0 -- sh -c "VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN='$root_token' vault auth enable kubernetes" >/dev/null 2>&1 || true
  kaws exec -n vault vault-0 -- sh -c "VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN='$root_token' vault write auth/kubernetes/config kubernetes_host=https://kubernetes.default.svc:443" >/dev/null
  kaws exec -i -n vault vault-0 -- sh -c "VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN='$root_token' vault policy write soar-engine -" >/dev/null <<'EOF'
path "secret/data/grafana-smtp-secret" {
  capabilities = ["read"]
}
EOF
  kaws exec -n vault vault-0 -- sh -c "VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN='$root_token' vault write auth/kubernetes/role/soar-engine bound_service_account_names=soar-engine bound_service_account_namespaces=plg-stack policies=soar-engine ttl=1h" >/dev/null
  kaws exec -n vault vault-0 -- sh -c "VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN='$root_token' vault kv put secret/grafana-smtp-secret password='${SMTP_PASS:-}'" >/dev/null

  ok "Vault ready: unsealed, kubernetes auth configured, grafana-smtp-secret seeded"
}

create_core_banking_integrity_secret() {
  local secret_value
  if kaws get secret core-banking-integrity-secret -n financial >/dev/null 2>&1; then
    secret_value="$(kaws -n financial get secret core-banking-integrity-secret -o jsonpath='{.data.shared-secret}' | base64 -d)"
    log "core-banking-integrity-secret already exists on AWS"
  else
    secret_value="$(openssl rand -hex 32 2>/dev/null || date +%s%N)"
    kaws create secret generic core-banking-integrity-secret -n financial \
      --from-literal=shared-secret="$secret_value"
    ok "core-banking-integrity-secret created on AWS"
  fi

  if kos get secret core-banking-integrity-secret -n financial >/dev/null 2>&1; then
    log "core-banking-integrity-secret already exists on OpenStack"
  else
    kos create secret generic core-banking-integrity-secret -n financial \
      --from-literal=shared-secret="$secret_value"
    ok "core-banking-integrity-secret created on OpenStack"
  fi
}

create_financial_runtime_secrets() {
  if kaws get secret web-portal-secret -n financial >/dev/null 2>&1; then
    log "web-portal-secret already exists"
    return
  fi

  local admin_password session_secret
  admin_password="$(keycloak_admin_password)"
  session_secret="$(openssl rand -hex 32 2>/dev/null || date +%s%N)"
  kaws create secret generic web-portal-secret -n financial \
    --from-literal=admin-password="$admin_password" \
    --from-literal=session-secret="$session_secret"
  ok "web-portal-secret created"
}

provision_grafana_configmaps() {
  log "Provisioning Grafana ConfigMaps"
  kaws delete configmap grafana-datasources grafana-dashboard-provider grafana-dashboards grafana-alerting \
    -n plg-stack 2>/dev/null || true

  kaws create configmap grafana-datasources -n plg-stack \
    --from-file=loki-datasource.yml="$REPO_ROOT/plg-stack/grafana/datasources/loki-datasource.yml"
  kaws create configmap grafana-dashboard-provider -n plg-stack \
    --from-file=dashboard-provider.yml="$REPO_ROOT/plg-stack/grafana/dashboards/dashboard-provider.yml"
  kaws create configmap grafana-dashboards -n plg-stack \
    --from-file=zta-security-overview.json="$REPO_ROOT/plg-stack/grafana/dashboards/zta-security-overview.json" \
    --from-file=ztlab-security-overview.json="$REPO_ROOT/plg-stack/grafana/dashboards/ztlab-security-overview.json" \
    --from-file=ztlab-full-logs.json="$REPO_ROOT/plg-stack/grafana/dashboards/ztlab-full-logs.json" \
    --from-file=envoy-access-logs.json="$REPO_ROOT/plg-stack/grafana/dashboards/envoy-access-logs.json" \
    --from-file=opa-decision-log.json="$REPO_ROOT/plg-stack/grafana/dashboards/opa-decision-log.json" \
    --from-file=threat-intel-feed.json="$REPO_ROOT/plg-stack/grafana/dashboards/threat-intel-feed.json" \
    --from-file=ztlab-soar-dashboard.json="$REPO_ROOT/plg-stack/grafana/dashboards/ztlab-soar-dashboard.json"
  kaws create configmap grafana-alerting -n plg-stack \
    --from-file=brute-force-alert.yml="$REPO_ROOT/plg-stack/grafana/alerting/brute-force-alert.yml" \
    --from-file=fraud-gate-bypass-alert.yml="$REPO_ROOT/plg-stack/grafana/alerting/fraud-gate-bypass-alert.yml" \
    --from-file=large-response-alert.yml="$REPO_ROOT/plg-stack/grafana/alerting/large-response-alert.yml" \
    --from-file=lateral-movement-alert.yml="$REPO_ROOT/plg-stack/grafana/alerting/lateral-movement-alert.yml" \
    --from-file=access-denied-alert.yml="$REPO_ROOT/plg-stack/grafana/alerting/access-denied-alert.yml" \
    --from-file=privilege-escalation-alert.yml="$REPO_ROOT/plg-stack/grafana/alerting/privilege-escalation-alert.yml" \
    --from-file=soar-engine-alert.yml="$REPO_ROOT/plg-stack/grafana/alerting/soar-engine-alert.yml" \
    --from-file=security-control-plane-alert.yml="$REPO_ROOT/plg-stack/grafana/alerting/security-control-plane-alert.yml" \
    --from-file=notification-policy.yml="$REPO_ROOT/plg-stack/grafana/alerting/notification-policy.yml"
}

deploy_observability_response() {
  step "Step 6: PLG, AI/SOAR, Prometheus"

  # redis-auth must exist in plg-stack (soar-engine + security-scorer reference it)
  kaws create secret generic redis-auth -n plg-stack \
    --from-literal=password="ZTALab-Redis-2026!" \
    --dry-run=client -o yaml | kaws apply -f -

  create_keycloak_admin_secret
  create_ai_secret
  create_smtp_secret
  deploy_vault_and_seed_secrets

  kaws apply -f "$REPO_ROOT/k8s/plg-stack/loki-configmap.yaml"
  kaws apply -f "$REPO_ROOT/k8s/plg-stack/loki.yaml"
  wait_deployment "$AWS_CONTEXT" plg-stack loki 180s

  provision_grafana_configmaps
  kaws apply -f "$REPO_ROOT/k8s/plg-stack/grafana.yaml"
  wait_deployment "$AWS_CONTEXT" plg-stack grafana 180s

  kaws apply -f "$REPO_ROOT/k8s/plg-stack/promtail-daemonset.yaml"
  wait_daemonset "$AWS_CONTEXT" plg-stack promtail 180s

  # Ensure socat relay is persistent on AWS worker (OpenStack Promtail → Loki cross-cluster)
  # aws_bastion's public IP is dynamic (not an EIP) and changes on every instance
  # recreate, so it must be resolved from inventory rather than hardcoded.
  LOKI_CIP=$(kubectl --context "$AWS_CONTEXT" -n plg-stack get svc loki -o jsonpath='{.spec.clusterIP}')
  AWS_BASTION_IP="$(ansible-inventory -i "$REPO_ROOT/ansible/inventory/hosts.yml" --host aws_bastion | python3 -c 'import json,sys; print(json.load(sys.stdin)["ansible_host"])')"
  ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i "$SSH_KEY" \
      -J "ubuntu@${AWS_BASTION_IP}" ubuntu@10.10.1.11 \
      "sudo tee /etc/systemd/system/loki-relay.service > /dev/null << 'EOF'
[Unit]
Description=Loki Relay (OpenStack cross-cluster)
After=network.target

[Service]
ExecStart=/usr/bin/socat TCP-LISTEN:31100,fork,reuseaddr TCP:${LOKI_CIP}:3100
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload && sudo systemctl enable --now loki-relay" 2>/dev/null || warn "socat relay setup skipped (SSH unavailable)"

  kos apply -f "$REPO_ROOT/k8s/plg-stack/promtail-daemonset.yaml"
  # 172.10.10.1:13099 = deployer machine br-exnat interface (reachable from OpenStack via os-gateway default route)
  # socat on deployer bridges this port to localhost:13100 → kubectl port-forward → Loki
  kos set env daemonset/promtail -n plg-stack LOKI_PUSH_URL=http://172.10.10.1:13099/loki/api/v1/push CLOUD_PROVIDER=openstack
  wait_daemonset "$OS_CONTEXT" plg-stack promtail 180s

  kaws apply -f "$REPO_ROOT/k8s/rbac/soar-rbac.yaml"
  kaws apply -f "$REPO_ROOT/k8s/rbac/web-portal-response-rbac.yaml"
  kaws apply -f "$REPO_ROOT/k8s/plg-stack/security-scorer.yaml"
  wait_deployment "$AWS_CONTEXT" plg-stack security-scorer 120s
  kaws apply -f "$REPO_ROOT/k8s/plg-stack/ai-analyzer.yaml"
  wait_deployment "$AWS_CONTEXT" plg-stack ai-analyzer 120s
  create_soar_main_patch_configmap
  create_soar_openstack_kubeconfig_secret
  kaws apply -f "$REPO_ROOT/k8s/plg-stack/ai-soar.yaml"
  wait_deployment "$AWS_CONTEXT" plg-stack soar-engine 180s

  kaws apply -f "$REPO_ROOT/k8s/monitoring/prometheus.yaml"
  wait_deployment "$AWS_CONTEXT" monitoring prometheus 180s

  ok "PLG, AI/SOAR, and Prometheus ready on AWS"
}

apply_policies_and_ingress() {
  step "Step 7: Ingress"
  # Network policies are applied earlier (apply_network_policies, right after
  # namespaces) so they exist before any pod with restricted egress starts —
  # see the plg-stack → vault NetworkPolicy race that broke soar-engine's
  # vault-fetch-secrets init container on 2026-08-21.
  kaws apply -f "$REPO_ROOT/k8s/ingress.yaml"
  ok "Ingress applied on AWS"
}

verify_final() {
  step "Step 8: Final status"

  log "AWS non-system pods"
  kaws get pods -A | grep -v kube-system || true

  log "OpenStack non-system pods"
  kos get pods -A | grep -v kube-system || true

  ok "Full multi-cloud deploy flow completed"
}

main() {
  step "Step 0: Prerequisites"
  require_cmd kubectl
  require_cmd bash
  require_cmd grep

  if [[ "$SKIP_TUNNEL" == false ]]; then
    "$REPO_ROOT/scripts/k8s-tunnel.sh" up all
  fi

  verify_context "$AWS_CONTEXT"
  verify_context "$OS_CONTEXT"

  regenerate_policy_files
  apply_namespaces
  apply_network_policies
  deploy_gatekeeper
  deploy_istio
  sync_images
  deploy_security_stack
  deploy_openldap_and_federation
  deploy_audience_mapper
  deploy_stepup_flow
  deploy_aws_saml_federation
  deploy_financial_infra
  deploy_financial_services
  deploy_observability_response
  apply_policies_and_ingress
  verify_final
}

main "$@"
