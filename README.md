# pigdns

🐷 PigDNS is a DNS server with Let's Encrypt integration

## Features

* Mimic behaviour of services like `nip.io` and `sslip.io`
* DOH (DNS over HTTPS) support
* Full recursive mode resolver (with in memory cache)
* Automagic Let's Encrypt certificate management for the handled domain and DOH (using the DNS01 challenge)
* Special cases handling using a standard zone file

## Getting started


```sh
docker compose up -d
```

This brings up a local full recursor whit a blocklist enabled

You can already query it with:

```sh
$ dig @127.0.0.1 google.com
```


### Example: Delegate a subdomain to pigdns.

Delegate `pig.yourdomain.io.` On your domain nameserver:

* add an A record that points to the IP address on which pigdns is listening 
* add an NS record that points to the pigdns server

| domain | record type | destination |
| ------ | ------------ | ----------- |  
| pigdns.yourdomain.io | A | 159.12.16.4 (put your pigdns server ip address here)
| pig.yourdomain.io | NS | pigdns.yourdomain.io
