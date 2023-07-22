package routes

import (
	"github.com/gin-gonic/gin"
)

type rootGroup struct{}

func RootRoutes(router *gin.RouterGroup) {
	r := &rootGroup{}

	router.GET("", r.root)
}

func (r *rootGroup) root(c *gin.Context) {
}
