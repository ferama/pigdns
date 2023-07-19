# pigdns


Delegate a subdomain to pigdns

Example:

Delegate pigdns.yourdomain.io. On your domain nameserver:

* add an A record pointing to the IP address on which pigdns is listening 
* add an NS record pointing to the pigdns server

| domain | record type | destination |
| ------ | ------------ | ----------- |  
| pigdns.yourdomain.io | A | 159.12.16.4
| pigdns.yourdomain.io | NS | pigdns.yourdomain.io
