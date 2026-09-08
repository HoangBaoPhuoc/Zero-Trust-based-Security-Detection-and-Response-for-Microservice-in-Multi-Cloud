# Envoy tự viết (đã ngừng dùng — chuyển sang Istio)

Các file trong thư mục này là cấu hình Envoy sidecar **tự viết** dùng ở giai đoạn trước khi hệ thống migrate sang Istio service mesh. Chúng **không còn được áp dụng bởi bất kỳ script deploy nào** kể từ khi migration hoàn tất (xem `scripts/deploy-security-stack.sh`, hàm `deploy_step_5_envoy()` đã bị xoá — comment tại đó xác nhận: "all 8 financial services on both clouds are migrated to Istio — nothing mounts the envoy-config ConfigMap anymore").

Xác nhận thực nghiệm (2026-09-05, xem `KET-QUA-KIEM-TRA.md` §T-0.1): mọi pod service nghiệp vụ trong namespace `financial`, cả cluster AWS lẫn OpenStack, đều chạy container `istio-proxy` — không còn pod nào dùng container Envoy tự viết.

Giữ lại các file này chỉ để tham khảo lịch sử (thiết kế mTLS/ext_authz trước khi có Istio). Không sửa, không áp dụng lại trừ khi có quyết định quay lại kiến trúc Envoy tự viết.

- `configmap.yaml` — cấu hình Envoy sidecar (SDS cluster, ext_authz filter trỏ tới OPA)
- `envoy-aws.yaml` — manifest triển khai Envoy sidecar phía AWS
- `envoy-os.yaml` — manifest triển khai Envoy sidecar phía OpenStack
