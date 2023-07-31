# pigdns

🐷 PigDNS is a DNS server that mimic the behaviour of services like:

* nip.io
* sslip.io

## Project STATUS
PigDNS is in early development stages


## Setup

* Delegate a subdomain to pigdns.
* Run `pigdns --domain <your domain>`

### Example:

Delegate `pig.yourdomain.io.` On your domain nameserver:

* add an A record that points to the IP address on which pigdns is listening 
* add an NS record that points to the pigdns server

| domain | record type | destination |
| ------ | ------------ | ----------- |  
| pigdns.yourdomain.io | A | 159.12.16.4 (put your pigdns server ip address here)
| pig.yourdomain.io | NS | pigdns.yourdomain.io


Run
```sh
$ pigdns --domain pig.yourdomain.io
```

## Query Examples

* 192-168-1-10.pig.yourdomain.io -> 192.168.10.1
* abc-192-168-1-10-def.pig.yourdomain.io -> 192.168.10.1