package web

import (
	"log"

	"github.com/ferama/pigdns/pkg/web/routes"
	"github.com/gin-gonic/gin"
)

const listenAddress = ":80"

type webServer struct {
	router *gin.Engine

	datadir string
	domain  string
}

func NewWebServer(datadir string, domain string) *webServer {

	gin.SetMode(gin.ReleaseMode)
	router := gin.Default()

	router.LoadHTMLGlob("pkg/web/templates/*")

	s := &webServer{
		router:  router,
		datadir: datadir,
		domain:  domain,
	}
	s.setupRoutes()

	log.Printf("web listening on '%s'", listenAddress)
	return s
}

func (s *webServer) setupRoutes() {
	// setup health endpoint
	s.router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "ok",
		})
	})

	routes.CertRoutes(s.datadir, s.router.Group("/certs"))
	routes.RootRoutes(s.domain, s.router.Group("/"))
}

func (s *webServer) Run() {
	s.router.Run(listenAddress)
}
