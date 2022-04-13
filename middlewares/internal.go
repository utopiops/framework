package middlewares

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func Internal() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		tokeType := ctx.MustGet("tokenType").(string)
		if tokeType != "internal" {
			ctx.JSON(http.StatusForbidden, gin.H{
				"error": "this is internal route",
			})
			return
		}
		ctx.Next()
	}
}
