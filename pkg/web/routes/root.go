package routes

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

func RootHandler(domain string, subdomain string, keyRequired bool, isHTTPS bool) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		protocol := "http"
		if isHTTPS {
			protocol = "https"
		}

		sub := ""
		if subdomain != "" {
			sub = fmt.Sprintf("%s.", subdomain)
		}

		ctx.HTML(http.StatusOK, "index.html", gin.H{
			"protocol":    protocol,
			"domain":      domain,
			"subdomain":   sub,
			"keyRequired": keyRequired,
		})
	}
}
