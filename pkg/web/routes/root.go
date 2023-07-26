package routes

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type rootGroup struct {
	domain string
}

func RootRoutes(domain string, router *gin.RouterGroup) {
	r := &rootGroup{
		domain: domain,
	}

	router.GET("", r.root)
}

func (r *rootGroup) root(c *gin.Context) {
	c.HTML(http.StatusOK, "index.html", gin.H{
		"domain": r.domain,
	})
}
