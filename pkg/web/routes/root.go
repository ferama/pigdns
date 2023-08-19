package routes

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func RootHandler(domain string, keyRequired bool) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		protocol := "https"

		ctx.HTML(http.StatusOK, "index.html", gin.H{
			"protocol":    protocol,
			"domain":      domain,
			"host":        ctx.Request.Host,
			"keyRequired": keyRequired,
		})
	}
}
