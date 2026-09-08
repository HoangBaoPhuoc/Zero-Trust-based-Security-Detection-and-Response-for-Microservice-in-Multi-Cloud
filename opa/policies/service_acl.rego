package zta.generated

# GENERATED FILE — KHÔNG SỬA TAY. Nguồn: policy/service-graph.yaml
# Sinh lại: python3 scripts/gen-rego-acl.py
#
# Ma trận phân quyền service-to-service (L7) — nguồn sự thật duy nhất, dùng
# chung bởi zta_policy.rego (cluster AWS) và cross_cloud.rego (cluster
# OpenStack) qua `import data.zta.generated`. Xem policy/service-graph.yaml
# để biết dữ liệu gốc + traffic thật đã đo (T-1.1, KET-QUA-KIEM-TRA.md).

service_acl := {
  "spiffe://ztlab.local/aws/api-gateway": {
    "spiffe://ztlab.local/aws/payment-service": {
      "GET": ["/accounts", "/transactions"],
      "POST": ["/payments"],
    },
  },
  "spiffe://ztlab.local/aws/payment-service": {
    "spiffe://ztlab.local/aws/fraud-detection": {
      "POST": ["/score"],
    },
    "spiffe://ztlab.local/aws/notification-service": {
      "POST": ["/notify"],
    },
    "spiffe://ztlab.local/openstack/core-banking": {
      "GET": ["/accounts", "/transactions"],
      "POST": ["/transactions/execute"],
    },
  },
  "spiffe://ztlab.local/aws/web-portal": {
    "spiffe://ztlab.local/aws/api-gateway": {
      "GET": ["/accounts", "/transactions"],
      "POST": ["/payments"],
    },
  },
  "spiffe://ztlab.local/openstack/core-banking": {
    "spiffe://ztlab.local/openstack/account-service": {
      "GET": ["/accounts"],
      "POST": ["/accounts/transfer"],
    },
    "spiffe://ztlab.local/openstack/transaction-service": {
      "GET": ["/transactions"],
      "POST": ["/transactions"],
    },
  },
}
