package web

import (
	"crypto/tls"
	"embed"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ferama/pigdns/pkg/certman"
	"github.com/ferama/pigdns/pkg/web/routes"
	"github.com/gin-gonic/gin"
)

//go:embed templates/*
var f embed.FS

type webServer struct {
	router *gin.Engine

	datadir   string
	domain    string
	subdomain string
	apikey    string
	useHTTPS  bool

	cachedCert        *tls.Certificate
	cachedCertModTime time.Time
}

func NewWebServer(datadir string, domain string, subdomain string, apikey string) *webServer {

	gin.SetMode(gin.ReleaseMode)
	router := gin.Default()
	templ := template.Must(template.New("").ParseFS(f, "templates/*.html"))
	router.SetHTMLTemplate(templ)

	s := &webServer{
		router:    router,
		datadir:   datadir,
		domain:    domain,
		apikey:    apikey,
		useHTTPS:  subdomain != "",
		subdomain: subdomain,
	}
	s.setupRoutes()
	return s
}

func (s *webServer) setupRoutes() {
	// setup health endpoint
	s.router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "ok",
		})
	})

	certsGroup := s.router.Group("/certs")
	if s.apikey != "" {
		certsGroup.Use(authMiddleware(s.apikey))
	}
	routes.CertRoutes(s.datadir, certsGroup)

	routes.RootRoutes(
		s.domain,
		s.subdomain,
		s.apikey != "",
		s.useHTTPS,
		s.router.Group("/"))
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

func (s *webServer) Run() {
	if !s.useHTTPS {
		log.Printf("web listening on ':80'")
		srv := http.Server{
			Addr:    ":80",
			Handler: s.router,
		}
		srv.ListenAndServe()
	}

	log.Printf("web listening on ':443'")
	go http.ListenAndServe(":80", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.subdomain != "" {
			if !strings.HasPrefix(r.Host, s.subdomain+".") {
				u := *r.URL
				u.Host = fmt.Sprintf("%s.%s", s.subdomain, r.Host)
				u.Scheme = "https"
				http.Redirect(w, r, u.String(), http.StatusFound)
				return
			}
		}
		http.Redirect(w, r, "https://"+r.Host+r.RequestURI, http.StatusMovedPermanently)
	}))

	srv := http.Server{
		Addr: ":443",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if s.subdomain != "" {
				if !strings.HasPrefix(r.Host, s.subdomain+".") {
					u := *r.URL
					u.Host = fmt.Sprintf("%s.%s", s.subdomain, r.Host)
					u.Scheme = "https"
					http.Redirect(w, r, u.String(), http.StatusFound)
					return
				}
			}

			s.router.ServeHTTP(w, r)
		}),
	}

	tlsConfig := &tls.Config{
		GetCertificate: s.getCertificates,
	}
	srv.TLSConfig = tlsConfig
	srv.ListenAndServeTLS("", "")
}
