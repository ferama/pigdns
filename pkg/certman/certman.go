package certman

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/mholt/acmez/acme"
)

const (
	// dev
	directoryStaging = "https://acme-staging-v02.api.letsencrypt.org/directory"

	// prod
	directory = "https://acme-v02.api.letsencrypt.org/directory"

	PrivKeyFilename   = "privkey.pem"
	FullChainFilename = "fullchain.pem"

	// if days left is less than this value,
	// a new certificate will be requested
	renewDaysBeforeExpires = 35
)

var CertmanMU sync.Mutex

func writeFile(datadir string, name string, content []byte) {
	path := filepath.Join(datadir, name)
	err := os.MkdirAll(datadir, os.ModePerm)
	if err != nil {
		log.Fatal().Msg(err.Error())
	}

	f, err := os.Create(path)
	if err != nil {
		log.Fatal().Msg(err.Error())
	}
	defer f.Close()

	_, err = f.Write(content)
	if err != nil {
		log.Fatal().Msg(err.Error())
	}
}

type Certman struct {
	domain     string
	datadir    string
	useStaging bool

	accountMan *accountMan
}

func New(domain string, datadir string, email string, useStaging bool) *Certman {
	c := &Certman{
		domain:     domain,
		datadir:    datadir,
		useStaging: useStaging,
		accountMan: &accountMan{
			datadir:    datadir,
			email:      email,
			useStaging: useStaging,
		},
	}
	if c.useStaging {
		log.Print("[certman] using STAGING le api")
	} else {
		log.Print("[certman] using PRODUCTION le api")
	}

	return c
}

func (c *Certman) getPrivateKey() (*ecdsa.PrivateKey, error) {
	certPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating certificate key: %v", err)
	}

	x509Encoded, _ := x509.MarshalPKCS8PrivateKey(certPrivateKey)
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded})
	writeFile(c.datadir, PrivKeyFilename, pemEncoded)

	return certPrivateKey, nil
}

func (c *Certman) needsRenew() bool {
	path := filepath.Join(c.datadir, FullChainFilename)
	if _, err := os.Stat(path); err == nil {
		pemEncoded, _ := os.ReadFile(path)
		block, _ := pem.Decode(pemEncoded)
		crt, _ := x509.ParseCertificate(block.Bytes)
		diff := time.Until(crt.NotAfter)
		expiresInDays := int(math.Round(diff.Hours() / 24))
		log.Info().Msgf(
			"[certman] cert -> Expires in: %d days, NotBefore: %s, NotAfter: %s",
			expiresInDays,
			crt.NotBefore,
			crt.NotAfter,
		)
		if expiresInDays > renewDaysBeforeExpires {
			return false
		}
	}

	return true
}

func (c *Certman) Run() {
	for {
		CertmanMU.Lock()
		if c.needsRenew() {
			err := c.renew()
			if err != nil {
				log.Print(err)
			}
		}
		CertmanMU.Unlock()
		time.Sleep(12 * time.Hour)
	}
}

func (c *Certman) renew() error {
	// a context allows us to cancel long-running ops
	ctx := context.Background()
	certPrivateKey, err := c.getPrivateKey()
	if err != nil {
		return fmt.Errorf("getting certificate key: %v", err)
	}

	domains := []string{
		// request a wildcard cert
		fmt.Sprintf("*.%s", c.domain),
	}
	// then you need a certificate request; here's a simple one - we need
	// to fill out the template, then create the actual CSR, then parse it
	csrTemplate := &x509.CertificateRequest{DNSNames: domains}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, certPrivateKey)
	if err != nil {
		return fmt.Errorf("generating CSR: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return fmt.Errorf("parsing generated CSR: %v", err)
	}

	// now we can make our low-level ACME client
	client := &acme.Client{
		Directory: directory,
	}
	if c.useStaging {
		client.Directory = directoryStaging
	}

	account, err := c.accountMan.get(ctx)
	if err != nil {
		return fmt.Errorf("new account: %v", err)
	}

	// now we can actually get a cert; first step is to create a new order
	var ids []acme.Identifier
	for _, domain := range domains {
		ids = append(ids, acme.Identifier{Type: "dns", Value: domain})
	}
	order := acme.Order{Identifiers: ids}
	order, err = client.NewOrder(ctx, *account, order)
	if err != nil {
		return fmt.Errorf("creating new order: %v", err)
	}

	// each identifier on the order should now be associated with an
	// authorization object; we must make the authorization "valid"
	// by solving any of the challenges offered for it
	for _, authzURL := range order.Authorizations {
		authz, err := client.GetAuthorization(ctx, *account, authzURL)
		if err != nil {
			return fmt.Errorf("getting authorization %q: %v", authzURL, err)
		}

		var challenge acme.Challenge
		for _, c := range authz.Challenges {
			if c.Type == acme.ChallengeTypeDNS01 {
				challenge = c
			}
		}

		// at this point, you must prepare to solve the challenge; how
		// you do this depends on the challenge (see spec for details).
		// usually this involves configuring an HTTP or TLS server, but
		// it might also involve setting a DNS record (which can take
		// time to propagate, depending on the provider!) - this example
		// does NOT do this step for you - it's "bring your own solver."

		// once you are ready to solve the challenge, let the ACME
		// server know it should begin
		challenge, err = client.InitiateChallenge(ctx, *account, challenge)
		if err != nil {
			return fmt.Errorf("initiating challenge %q: %v", challenge.URL, err)
		}

		// now the challenge should be under way; at this point, we can
		// continue initiating all the other challenges so that they are
		// all being solved in parallel (this saves time when you have a
		// large number of SANs on your certificate), but this example is
		// simple, so we will just do one at a time; we wait for the ACME
		// server to tell us the challenge has been solved by polling the
		// authorization status

		Token().Set(challenge.DNS01KeyAuthorization())

		authz, err = client.PollAuthorization(ctx, *account, authz)
		if err != nil {
			log.Printf("[certman] %s\n", err)
			return err
		}
		log.Printf("[certman] expecting record: %s TXT %s", challenge.DNS01TXTRecordName(), challenge.DNS01KeyAuthorization())

		// if we got here, then the challenge was solved successfully, hurray!
	}

	// to request a certificate, we finalize the order; this function
	// will poll the order status for us and return once the cert is
	// ready (or until there is an error)
	order, err = client.FinalizeOrder(ctx, *account, order, csr.Raw)
	if err != nil {
		return fmt.Errorf("finalizing order: %v", err)
	}

	// we can now download the certificate; the server should actually
	// provide the whole chain, and it can even offer multiple chains
	// of trust for the same end-entity certificate, so this function
	// returns all of them; you can decide which one to use based on
	// your own requirements
	certChains, err := client.GetCertificateChain(ctx, *account, order.Certificate)
	if err != nil {
		return fmt.Errorf("downloading certs: %v", err)
	}

	// all done! store it somewhere safe, along with its key
	cert := certChains[0]
	log.Printf("[certman] got certificate %q\n", cert.URL)
	writeFile(c.datadir, FullChainFilename, cert.ChainPEM)

	return nil
}
