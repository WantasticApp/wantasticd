Copy each `clientN.conf.example` to `clientN.conf` and supply a newly generated
private key (`wg genkey`). Register its public key with your local test hub and
adjust the peer public key, addresses, and endpoint for that hub.

The `.conf` files are ignored and must never be committed. Templates deliberately
contain an invalid private-key placeholder so they cannot connect accidentally.
Previously committed test keys must not be reused on a real network.
