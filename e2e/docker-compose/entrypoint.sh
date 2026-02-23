#!/bin/sh
rm -rf /etc/dropbear
mkdir -p /etc/dropbear
dropbearkey -t rsa -f /etc/dropbear/dropbear_rsa_host_key
dropbearkey -t ecdsa -f /etc/dropbear/dropbear_ecdsa_host_key
dropbearkey -t ed25519 -f /etc/dropbear/dropbear_ed25519_host_key

# Set root password to "root" by editing the shadow file
sed -i 's/^root:[^:]*:/root:$1$V4UetPzk$CYXlsBSmUtsgE9KBAbkR9\/:/' /etc/shadow

# Start dropbear in the background
/usr/sbin/dropbear -B -p 22

# Execute the main command (wantasticd)
exec "$@"
