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
}

func NewWebServer(datadir string) *webServer {

	gin.SetMode(gin.ReleaseMode)
	ginrouter := gin.Default()

	s := &webServer{
		router:  ginrouter,
		datadir: datadir,
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
}

func (s *webServer) Run() {
	s.router.Run(listenAddress)
}
