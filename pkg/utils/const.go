package utils

const (
	// common
	DatadirFlag  = "datadir"
	DomainFlag   = "domain"
	PortFlag     = "port"
	ZoneFileFlag = "zone-file"

	// forwarder
	ResolverEnableFlag    = "forward-enable"
	ResolverAllowNetworks = "forward-allow-nets"

	// certmanager
	CertmanEmailFlag      = "certman-email"
	CertmanUseStagingFlag = "certman-use-staging"
	CertmanEnableFlag     = "certman-enable"

	// web
	WebEnableFlag    = "web-enable"
	WebApiKeyFlag    = "web-api-key"
	WebSubdomainFlag = "web-subdomain"
)
