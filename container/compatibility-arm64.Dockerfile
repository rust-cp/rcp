# Native ARM64 qualification environment only; no distribution or publication.
FROM registry.access.redhat.com/ubi9/ubi-minimal@sha256:a28d61d9531d13cb1c0a70d2e9f214aee029db73b614149122747905d973de74
COPY container/compatibility-arm64-packages.lock /tmp/compatibility-packages.lock
RUN microdnf install -y $(cat /tmp/compatibility-packages.lock) && rpm -q $(cat /tmp/compatibility-packages.lock) && microdnf clean all
