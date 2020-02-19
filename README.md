# Registration plateform for Personal Box

This server provide 2 core functionnalities.

## IPs publication

DNS protocol will be used to access a service deployed by a user on his cluster.
To avoid to host and ocnfigured a DNS server per cluster (which can be imposible in some cases), we will use a centralized name serveur.
An user should be able to publish it's public IP on the plateform, which will update DNS entries corresponding.

For example, if a use michel register itself, he will then be able to publish his IPs on the domain michel.pbox.io.

## Public keys

The other functionnality is to publish user's public keys.
By doing so, an user can share his machine with an other used with the name and platform name only. The machine will then fetch the public keys of the user to keep them in a local file to use for authentication.
As it, if the user add or revoke a public key, there will be no need of manual intervention to update the keys on each platform.
