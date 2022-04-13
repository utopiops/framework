package middlewares

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/utopiops/framework/utils"
)

type IdsMiddleware struct {
	publicUrl string
	adminUrl  string
	jwksUrl   string
}

func NewIdsMiddleware(publicUrl, adminUrl, jwksUrl string) *IdsMiddleware {
	return &IdsMiddleware{
		publicUrl: publicUrl,
		adminUrl:  adminUrl,
		jwksUrl:   jwksUrl,
	}
}

func (idsMiddleware *IdsMiddleware) IdsAuthorizationMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.Request.Header.Get("Authorization")
		if authHeader == "" {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		tokenString := strings.TrimSpace(strings.SplitN(authHeader, "Bearer", 2)[1])

		method := http.MethodPost
		url := fmt.Sprintf("%s/oauth2/introspect", idsMiddleware.adminUrl)
		accessTokenHeaders := []utils.Header{
			{
				Key:   "Content-Type",
				Value: "application/x-www-form-urlencoded",
			},
		}
		// send a POST request to ids admin url to introspect access token and check validity
		httpHelper := utils.NewHttpHelper(utils.NewHttpClient())
		out, err, statusCode, _ := httpHelper.HttpRequest(method, url, bytes.NewBuffer([]byte(fmt.Sprintf("token=%s", tokenString))), accessTokenHeaders, 0)
		if err != nil || statusCode != http.StatusOK {
			err = errors.New("can't get correct response from ids server")
			log.Println(err.Error())
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		var introspectResponse map[string]interface{}
		err = json.Unmarshal(out, &introspectResponse)
		if err != nil {
			err = errors.New("can't unmarshal response")
			log.Println(err.Error())
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		// check validity of access token
		if introspectResponse["active"] == false {
			err = errors.New("access token invalid/expired")
			log.Println(err.Error())
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		c.Set("tokenString", tokenString)
		exts, ok := introspectResponse["ext"]
		var kind string
		if ok {
			extParams := exts.(map[string]interface{})
			if extParams["external"].(bool) {
				kind = "external"
			} else {
				kind = "internal"
			}
		} else {
			kind = "internal"
		}

		c.Set("tokenType", kind)
		if kind == "external" {
			idToken, err := c.Cookie("id_token")
			if err != nil {
				log.Println(err.Error())
				c.AbortWithStatus(http.StatusBadRequest)
				return
			}

			accountId, err := utils.GetAccountId(idToken, idsMiddleware.jwksUrl)
			if err != nil {
				log.Println(err.Error())
				c.AbortWithStatus(http.StatusUnauthorized)
				return
			}
			c.Set("accountId", accountId)

			userId, err := utils.GetUserId(idToken, idsMiddleware.jwksUrl)
			if err != nil {
				log.Println(err.Error())
				c.AbortWithStatus(http.StatusUnauthorized)
				return
			}
			c.Set("userId", userId)

			plan, err := utils.GetPlan(idToken, idsMiddleware.jwksUrl)
			if err != nil {
				log.Println(err.Error())
				c.AbortWithStatus(http.StatusUnauthorized)
				return
			}
			c.Set("plan", plan)

			role, err := utils.GetRole(idToken, idsMiddleware.jwksUrl)
			if err != nil && err.Error() != "claim not found" {
				log.Println(err.Error())
				c.AbortWithStatus(http.StatusUnauthorized)
				return
			}
			if err == nil {
				c.Set("role", role)
			} else {
				c.Set("role", "")
			}
		}
		c.Next()
	}
}
