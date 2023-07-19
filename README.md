# pigdns

🐷 PigDNS is DNS server that mimic the behaviour of services like:

* nip.io
* sslip.io


## Setup

Delegate a subdomain to pigdns

Example:

Delegate pigdns.yourdomain.io. On your domain nameserver:

* add an A record pointing to the IP address on which pigdns is listening 
* add an NS record pointing to the pigdns server

| domain | record type | destination |
| ------ | ------------ | ----------- |  
| pigdns.yourdomain.io | A | 159.12.16.4
| pigdns.yourdomain.io | NS | pigdns.yourdomain.io


## Examples resolve

* 192.168.10.1.yourdomain.io -> 192.168.10.1
* abc-192.168.10.1.yourdomain.io -> 192.168.10.1
* abc-192-168-1-10-def.yourdomain.io -> 192.168.10.1