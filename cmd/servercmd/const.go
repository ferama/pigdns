package servercmd

const (
	// common
	Debug             = "debug"
	DatadirFlag       = "datadir"
	DomainFlag        = "domain"
	ListenAddressFlag = "listen-address"
	ZoneFileFlag      = "zone-file"

	// Standard DNS server. If true and the resolver is enabled
	// the standard (tcp and udp) dns server, will handle it
	DnsServeResolverEnable = "dns-serve-resolver"

	// resolver
	ResolverEnableFlag    = "resolver-enable"
	ResolverAllowNetworks = "resolver-allow-nets"

	// certmanager
	CertmanEmailFlag      = "certman-email"
	CertmanUseStagingFlag = "certman-use-staging"
	CertmanEnableFlag     = "certman-enable"

	// web
	WebCertsEnableFlag  = "web-certs-enable"
	WebCertsApiKeyFlag  = "web-certs-api-key"
	WebDohEnableFlag    = "web-doh-enable"
	WebHTTPSDisableFlag = "web-https-disable"
)
