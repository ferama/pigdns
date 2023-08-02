package routes

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

type rootGroup struct {
	domain      string
	subdomain   string
	keyRequired bool
	isHTTPS     bool
}

func RootRoutes(
	domain string,
	subdomain string,
	keyRequired bool,
	isHTTPS bool, router *gin.RouterGroup) {

	r := &rootGroup{
		domain:      domain,
		subdomain:   subdomain,
		keyRequired: keyRequired,
		isHTTPS:     isHTTPS,
	}

	router.GET("", r.root)
}

func (r *rootGroup) root(c *gin.Context) {
	protocol := "http"
	if r.isHTTPS {
		protocol = "https"
	}

	sub := ""
	if r.subdomain != "" {
		sub = fmt.Sprintf("%s.", r.subdomain)
	}

	c.HTML(http.StatusOK, "index.html", gin.H{
		"protocol":    protocol,
		"domain":      r.domain,
		"subdomain":   sub,
		"keyRequired": r.keyRequired,
	})
}
