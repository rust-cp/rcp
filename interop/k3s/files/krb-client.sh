#!/bin/sh
# The Kerberos client: the system GSSAPI library a dynamically linked rcp loads, and a ticket
# for rcpuser once the KDC answers. Ready when the ticket is in the cache.
set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get -qq update
apt-get -qq install -y --no-install-recommends krb5-user libgssapi-krb5-2 >/dev/null
cp /etc/rcp-krb/krb5.conf /etc/krb5.conf
until kinit rcpuser </etc/rcp-krb-secret/user >/dev/null 2>&1; do sleep 2; done
klist -s
touch /tmp/ready
exec sleep infinity
