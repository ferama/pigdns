package main

const (
	// common
	DebugFlag         = "debug"
	InfoFlag          = "info"
	DatadirFlag       = "datadir"
	DomainFlag        = "domain"
	ListenAddressFlag = "listen-address"
	ZoneFileFlag      = "zone-file"

	// Standard DNS server. If true and the resolver is enabled
	// the standard (tcp and udp) dns server, will handle it
	DnsServeRecursorEnable = "dns-serve-recursor"

	// resolver
	RecursorEnableFlag    = "recursor-enable"
	RecursorAllowNetworks = "recursor-allow-nets"

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
