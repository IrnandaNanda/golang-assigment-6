package middleware

import (
	"a21hc3NpZ25tZW50/model"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
)

func Auth() gin.HandlerFunc {
	return gin.HandlerFunc(func(ctx *gin.Context) {
		// Abaikan middleware untuk rute tertentu
		if ctx.Request.URL.Path == "/user/register" || ctx.Request.URL.Path == "/user/login" {
			ctx.Next()
			return
		}

		// Ambil cookie session_token
		cookie, err := ctx.Cookie("session_token")
		if err != nil {
			handleCookieError(ctx, err)
			return
		}

		// Parse token JWT dengan klaim
		tokenClaims := model.Claims{}
		token, err := jwt.ParseWithClaims(cookie, &tokenClaims, func(token *jwt.Token) (interface{}, error) {
			return model.JwtKey, nil
		})
		if err != nil || !token.Valid {
			handleTokenError(ctx, err)
			return
		}

		// Set UserID ke context jika valid
		if tokenClaims.UserID == 0 {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "Unauthorized: invalid user ID",
			})
			return
		}

		ctx.Set("id", tokenClaims.UserID)

		// Panggil middleware berikutnya
		ctx.Next()
	})
}

// handleCookieError menangani error saat membaca cookie
func handleCookieError(ctx *gin.Context, err error) {
	if err == http.ErrNoCookie {
		if ctx.Request.Header.Get("Content-Type") == "application/json" {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "Unauthorized: no cookie",
			})
			return
		}
		ctx.Redirect(http.StatusSeeOther, "/login")
		return
	}
	ctx.JSON(http.StatusBadRequest, gin.H{
		"error": "Bad Request",
	})
	ctx.Abort()
}

// handleTokenError menangani error saat memvalidasi token
func handleTokenError(ctx *gin.Context, err error) {
	if err == jwt.ErrSignatureInvalid {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			"error": "Unauthorized: invalid signature",
		})
		return
	}
	ctx.JSON(http.StatusBadRequest, gin.H{
		"error": "Bad Request",
	})
	ctx.Abort()
}
