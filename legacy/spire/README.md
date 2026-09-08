# Legacy SPIRE registration scripts

`register-aws-workloads.sh` and `register-os-workloads.sh` are **not invoked
anywhere** in the current deploy pipeline (confirmed by grep across
`scripts/`, `ansible/` — 2026-09-05). They predate the current registration
mechanism and are kept here only for historical reference.

**Why they were retired (T-2.2, `KE-HOACH-SUA-HE-THONG.md`):**
`register-aws-workloads.sh` parents each workload entry to a specific SPIRE
agent SPIFFE ID that embeds the EC2 node's UUID
(`.../aws-k3s/3548edb2-d8fb-46e0-a55d-ffd3a4b170c2`, hardcoded). Any time the
underlying node is replaced (new EC2 instance from a fresh `terraform apply`,
autoscaling replacement, etc.), that UUID changes and every entry parented to
it stops matching — SVID issuance breaks until someone notices and manually
re-registers with the new UUID. Confirmed live on 2026-09-05: after a full
`terraform apply`-from-scratch redeploy, the real attested agent UUIDs
(`dc8b2e90-...`, `b6b2cd22-...`, `0c5e47ee-...`) matched **none** of the UUIDs
hardcoded in this script — yet the mesh worked perfectly, because nothing
actually calls it. `register-os-workloads.sh` has the same problem, in an
even more broken form (its `parentID` is a literal placeholder path,
`.../os-k3s/spire/spire-agent`, not even a real UUID).

**What replaced them:** `scripts/ensure-spire-entries.sh`, invoked
unconditionally on every run of both `scripts/deploy-app.sh`
(`deploy_financial_services()`) and `scripts/deploy-security-stack.sh`. It
registers one **node alias** entry per cluster
(`spiffe://ztlab.local/nodes/aws-k3s`, `.../nodes/os-k3s`), selected by
`k8s_psat:cluster:<name>` — a selector every agent in that cluster satisfies
regardless of its own node UUID — and parents every workload entry to that
alias instead of to an individual agent. New nodes, replaced nodes, or a
wiped `spire-server` datastore all self-heal on the next deploy run, with no
manual UUID bookkeeping. This is the node-alias pattern; it achieves the same
node-UUID independence the plan's T-2.2 suggested via `ClusterSPIFFEID` CRD +
SPIRE Controller Manager, without needing that extra component.

See `KET-QUA-KIEM-TRA.md` (GIAI ĐOẠN 2, T-2.2) for the live verification.
