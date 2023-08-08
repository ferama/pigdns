package routes

import (
	"net/http"
	"os"
	"path/filepath"

	"github.com/ferama/pigdns/pkg/certman"
	"github.com/gin-gonic/gin"
)

type certGroup struct {
	datadir string
}

// Routes setup the root api routes
func CertRoutes(datadir string, router *gin.RouterGroup) {
	r := &certGroup{
		datadir: datadir,
	}

	router.GET(certman.FullChainFilename, r.fullchain)
	router.GET(certman.PrivKeyFilename, r.privkey)
}

func (r *certGroup) readFile(filename string) ([]byte, error) {
	path := filepath.Join(r.datadir, filename)
	_, err := os.Stat(path)
	if err == nil {
		return os.ReadFile(path)
	}
	return []byte{}, err
}

func (r *certGroup) fullchain(c *gin.Context) {
	certman.CertmanMU.Lock()
	defer certman.CertmanMU.Unlock()

	content, err := r.readFile(certman.FullChainFilename)
	if err == nil {
		c.Data(http.StatusOK, gin.MIMEPlain, content)
	} else {
		c.AbortWithError(http.StatusNotFound, err)
	}
}

func (r *certGroup) privkey(c *gin.Context) {
	certman.CertmanMU.Lock()
	defer certman.CertmanMU.Unlock()

	content, err := r.readFile(certman.PrivKeyFilename)
	if err == nil {
		c.Data(http.StatusOK, gin.MIMEPlain, content)
	} else {
		c.AbortWithError(http.StatusNotFound, err)
	}
}
