package web

import (
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/ferama/pigdns/pkg/certman"
	"github.com/gin-gonic/gin"
)

const listenAddress = ":80"

type webServer struct {
	router *gin.Engine

	datadir string
}

func NewWebServer(datadir string) *webServer {

	// Install admin apis
	gin.SetMode(gin.ReleaseMode)
	ginrouter := gin.Default()
	// ginrouter := gin.New()
	// ginrouter.Use(
	// 	// do not log k8s calls to health
	// 	// gin.LoggerWithWriter(gin.DefaultWriter, "/health"),
	// 	gin.Recovery(),
	// )

	s := &webServer{
		router:  ginrouter,
		datadir: datadir,
	}
	s.setupRoutes()

	log.Printf("web listening on '%s'", listenAddress)
	return s
}

func (s *webServer) readFile(filename string) ([]byte, error) {
	path := filepath.Join(s.datadir, filename)
	_, err := os.Stat(path)
	if err == nil {
		return os.ReadFile(path)
	}
	return []byte{}, err
}

func (s *webServer) setupRoutes() {
	// setup health endpoint
	s.router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "ok",
		})
	})

	s.router.GET("/certs/"+certman.FullChainFilename, func(c *gin.Context) {
		certman.CertmanMU.Lock()
		defer certman.CertmanMU.Unlock()

		content, err := s.readFile(certman.FullChainFilename)
		if err == nil {
			c.Data(http.StatusOK, gin.MIMEPlain, content)
		} else {
			c.AbortWithError(http.StatusNotFound, err)
		}
	})

	s.router.GET("/certs/"+certman.PrivKeyFilename, func(c *gin.Context) {
		certman.CertmanMU.Lock()
		defer certman.CertmanMU.Unlock()

		content, err := s.readFile(certman.PrivKeyFilename)
		if err == nil {
			c.Data(http.StatusOK, gin.MIMEPlain, content)
		} else {
			c.AbortWithError(http.StatusNotFound, err)
		}
	})
}

func (s *webServer) Run() {
	s.router.Run(listenAddress)
}
