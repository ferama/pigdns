package web

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/ferama/pigdns/pkg/certman"
	"github.com/ferama/pigdns/pkg/web/routes"
	"github.com/gin-gonic/gin"
	"github.com/miekg/dns"
	"github.com/rs/zerolog/log"
)

type webServer struct {
	router *gin.Engine

	datadir string
	domain  string

	cachedCert        *tls.Certificate
	cachedCertModTime time.Time
}

func NewWebServer(
	dnsMux *dns.ServeMux,
	datadir string,
	domain string) *webServer {

	gin.SetMode(gin.ReleaseMode)

	router := gin.New()
	router.Use(gin.Recovery())

	// router := gin.Default()

	s := &webServer{
		router:  router,
		datadir: datadir,
		domain:  domain,
	}
	s.setupRoutes(dnsMux)
	return s
}

func (s *webServer) setupRoutes(dnsMux *dns.ServeMux) {
	// setup health endpoint
	s.router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "ok",
		})
	})

	// install doh routes
	s.router.GET("/dns-query", routes.DohHandler(dnsMux))
	// the RFC8484 indicates this path for post requests
	s.router.POST("/dns-query", routes.DohHandler(dnsMux))
	// chrome seems to query to the root path instead... I'm missing something?
	s.router.POST("/", routes.DohHandler(dnsMux))
}

func (s *webServer) getCertificates(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
	keyFile := filepath.Join(s.datadir, certman.PrivKeyFilename)
	chainFile := filepath.Join(s.datadir, certman.FullChainFilename)
	stat, err := os.Stat(keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed checking key file modification time: %w", err)
	}
	if s.cachedCert == nil || stat.ModTime().After(s.cachedCertModTime) {
		pair, err := tls.LoadX509KeyPair(chainFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("failed loading tls key pair: %w", err)
		}

		s.cachedCert = &pair
		s.cachedCertModTime = stat.ModTime()
	}
	return s.cachedCert, nil
}

func (s *webServer) Start() {
	log.Info().Msg("web listening on ':443'")
	go http.ListenAndServe(":80", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://"+r.Host+r.RequestURI, http.StatusMovedPermanently)
	}))

	srv := http.Server{
		Addr: ":443",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s.router.ServeHTTP(w, r)
		}),
	}

	tlsConfig := &tls.Config{
		GetCertificate: s.getCertificates,
	}
	srv.TLSConfig = tlsConfig
	srv.ListenAndServeTLS("", "")
}
