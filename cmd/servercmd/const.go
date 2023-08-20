package servercmd

const (
	// common
	Debug             = "debug"
	DatadirFlag       = "datadir"
	DomainFlag        = "domain"
	ListenAddressFlag = "listen-address"
	ZoneFileFlag      = "zone-file"

	// Standard DNS server (udp and tcp)
	DnsEnable = "dns-enable"

	// resolver
	ResolverEnableFlag    = "resolver-enable"
	ResolverAllowNetworks = "resolver-allow-nets"

	// certmanager
	CertmanEmailFlag      = "certman-email"
	CertmanUseStagingFlag = "certman-use-staging"
	CertmanEnableFlag     = "certman-enable"

	// web
	WebCertsEnableFlag = "web-certs-enable"
	WebCertsApiKeyFlag = "web-certs-api-key"
	WebDohEnableFlag   = "web-doh-enable"
)
