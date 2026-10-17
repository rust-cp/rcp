# Test environment only; not the distributed scratch image.
FROM registry.access.redhat.com/ubi9/ubi-minimal@sha256:eba570d04193d1523a8576b1c0ff00e681c9edb1a41d4742559b6e3ff457601e
COPY container/compatibility-packages.lock /tmp/compatibility-packages.lock
RUN microdnf install -y $(cat /tmp/compatibility-packages.lock) && rpm -q $(cat /tmp/compatibility-packages.lock) && microdnf clean all
