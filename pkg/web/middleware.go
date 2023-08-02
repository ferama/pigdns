package web

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func authMiddleware(validKey string) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		APIKey := ctx.Request.Header.Get("X-API-Key")
		if APIKey != validKey {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"status": 401, "message": "Authentication failed"})
			return
		}
		ctx.Next()
	}
}
