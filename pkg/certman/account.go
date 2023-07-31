package certman

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"github.com/mholt/acmez/acme"
)

type accountMan struct {
	email      string
	datadir    string
	useStaging bool
}

func (a *accountMan) get(ctx context.Context) (*acme.Account, error) {
	accountPrivKeyFilename := fmt.Sprintf("%s.pem", a.email)
	path := filepath.Join(a.datadir, accountPrivKeyFilename)
	if _, err := os.Stat(path); err == nil {
		pemEncoded, _ := os.ReadFile(path)
		block, _ := pem.Decode([]byte(pemEncoded))
		x509Encoded := block.Bytes
		accountPrivateKey, err := x509.ParsePKCS8PrivateKey(x509Encoded)
		if err != nil {
			return nil, err
		}

		client := &acme.Client{
			Directory: directory,
		}
		if a.useStaging {
			client.Directory = directoryStaging
		}

		account := acme.Account{
			Contact:              []string{"mailto:" + a.email},
			TermsOfServiceAgreed: true,
			PrivateKey:           accountPrivateKey.(crypto.Signer),
		}

		account, err = client.GetAccount(ctx, account)
		if err != nil {
			return nil, err
		}

		if account.Status == acme.StatusValid {
			return &account, nil
		}
	}

	return a.create(ctx)
}

func (a *accountMan) create(ctx context.Context) (*acme.Account, error) {

	// before you can get a cert, you'll need an account registered with
	// the ACME CA - it also needs a private key and should obviously be
	// different from any key used for certificates!
	accountPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating account key: %v", err)
	}

	x509Encoded, _ := x509.MarshalPKCS8PrivateKey(accountPrivateKey)
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded})
	accountPrivKeyFilename := fmt.Sprintf("%s.pem", a.email)
	writeFile(a.datadir, accountPrivKeyFilename, pemEncoded)

	account := acme.Account{
		Contact:              []string{"mailto:" + a.email},
		TermsOfServiceAgreed: true,
		PrivateKey:           accountPrivateKey,
	}

	client := &acme.Client{
		Directory: directory,
	}
	if a.useStaging {
		client.Directory = directoryStaging
	}

	// if the account is new, we need to create it; only do this once!
	// then be sure to securely store the account key and metadata so
	// you can reuse it later!
	account, err = client.NewAccount(ctx, account)
	if err != nil {
		return nil, fmt.Errorf("%v", err)
	}

	return &account, nil
}
