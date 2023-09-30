# pigdns

🐷 PigDNS is a DNS server with Let's Encrypt integration

## Features

* Mimic behaviour of services like `nip.io` and `sslip.io`
* DOH (DNS over HTTPS) support
* Full recursive mode resolver (with in memory cache)
* Automagic Let's Encrypt certificate management for the handled domain and DOH (using the DNS01 challenge)
* Special cases handling using a standard zone file

## Setup

Start with a basic conf file
```yaml
middlewares:
  zone:
    enabled: true
    regexIPEnabled: true
    zoneFilePath: ./hack/zone.conf

    name: <your-domain>
```

Delegate a subdomain to pigdns.

### Example:

Delegate `pig.yourdomain.io.` On your domain nameserver:

* add an A record that points to the IP address on which pigdns is listening 
* add an NS record that points to the pigdns server

| domain | record type | destination |
| ------ | ------------ | ----------- |  
| pigdns.yourdomain.io | A | 159.12.16.4 (put your pigdns server ip address here)
| pig.yourdomain.io | NS | pigdns.yourdomain.io
