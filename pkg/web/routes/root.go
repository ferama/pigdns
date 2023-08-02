package routes

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type rootGroup struct {
	domain      string
	keyRequired bool
	https       bool
}

func RootRoutes(domain string, keyRequired bool, https bool, router *gin.RouterGroup) {
	r := &rootGroup{
		domain:      domain,
		keyRequired: keyRequired,
		https:       https,
	}

	router.GET("", r.root)
}

func (r *rootGroup) root(c *gin.Context) {
	protocol := "http"
	if r.https {
		protocol = "https"
	}
	c.HTML(http.StatusOK, "index.html", gin.H{
		"protocol":    protocol,
		"domain":      r.domain,
		"keyRequired": r.keyRequired,
	})
}
