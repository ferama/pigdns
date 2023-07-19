# pigdns

🐷 PigDNS is a DNS server that mimic the behaviour of services like:

* nip.io
* sslip.io


## Setup

* Delegate a subdomain to pigdns.
* Run `pigdns -domain <your domain>`

### Example:

Delegate `pigdns.yourdomain.io.` On your domain nameserver:

* add an A record pointing to the IP address on which pigdns is listening 
* add an NS record pointing to the pigdns server

| domain | record type | destination |
| ------ | ------------ | ----------- |  
| pigdns.yourdomain.io | A | 159.12.16.4
| pigdns.yourdomain.io | NS | pigdns.yourdomain.io


Run
```sh
$ pigdns -domain pigdns.yourdomain.io.
```

## Query Examples

* 192.168.10.1.pigdns.yourdomain.io -> 192.168.10.1
* abc-192.168.10.1.pigdns.yourdomain.io -> 192.168.10.1
* abc-192-168-1-10-def.pigdns.yourdomain.io -> 192.168.10.1