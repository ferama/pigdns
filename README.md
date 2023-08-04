# pigdns

🐷 PigDNS is a DNS server that mimic the behaviour of services like:

* nip.io
* sslip.io

It also includes:

* Automagic Let's Encrypt certificate management for the handled domain (using the DNS01 challenge)
* A friendly page to get always fresh certificates
* Special cases handling using a standard zone file

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


#### Query Examples

```
$ dig +short 192-168-1-10.pig.yourdomain.io
192.168.1.10

$ dig +short abc-192-168-1-10-def.pig.yourdomain.io
192.168.10.1

$ dig +short 2a01-4f8-c17-b8f--2.pig.yourdomain.io
2a01:4f8:c17:b8f::2
```

## Advanced setup with a custom zone file

`pigdns` can handle static zone file defined records too. The zone file
is monitored and changes will be loaded at runtime

```sh
$ pigdns --domain pig.yourdomain.io -z ./zone.conf
```

The `zone.conf` file:
```ini
$TTL    30M
            IN  NS      pigdns.io.
            IN  A       192.168.200.200

www         IN  A       127.0.0.1
; nested cnames
a           IN  A       192.168.100.1
b		   	IN  CNAME   a
c           IN  CNAME   b
; multiple records for the same subdomain
abc         IN  A       192.168.100.3
abc         IN  A       192.168.100.4
; aaaa records
aaaa        IN  AAAA    2a01:4f8:c17:b8f::2
bbbb        IN  CNAME   aaaa
```

Now you can query for
```
$ dig +short abc.pig.yourdomain.io
192.168.100.3
192.168.100.4
```

## Enable web page and http certificates download

`pigdns` uses Let's Encrypt and the DNS01 challenge to always keep up to date
certificates valid for the handled subdomain.

Certificates are stored on disk and can (optionally) be served through http.
Enable web page:

```sh
$ pigdns \
    --domain pig.yourdomain.io \
    -z ./zone.conf \
    -w -b www \
    -k <your complex api key here>
```

The `-b www` option, tells pigdns to serve the webpage under the www subdomain. This allows
pigdns to use valid (self managed) https certificates. You must configure the `zone.conf` 
accordingly to support the www subdomain.

You are strongly adviced to use an api key to serve the certifcates if pigdns http/https ports
are exposed to the internet.
