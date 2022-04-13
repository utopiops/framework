package middlewares

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"gitlab.com/utopiops-water/framework/utils"
)

type TempIdsMiddleware struct {
	publicUrl           string
	adminUrl            string
	jwksUrl             string
	authServerJwtSecret string
}

func NewTempIdsMiddleware(publicUrl, adminUrl, jwksUrl, authServerJwtSecret string) *TempIdsMiddleware {
	return &TempIdsMiddleware{
		publicUrl:           publicUrl,
		adminUrl:            adminUrl,
		jwksUrl:             jwksUrl,
		authServerJwtSecret: authServerJwtSecret,
	}
}

func (tempIdsMiddleware *TempIdsMiddleware) IdsAuthorizationMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.Request.Header.Get("Authorization")
		if authHeader == "" {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		tokenString := strings.TrimSpace(strings.SplitN(authHeader, "Bearer", 2)[1])
		c.Set("tokenString", tokenString)
		authenticated := false

		// start JWT middleware

		// Parse takes the token string and a function for looking up the key. The latter is especially
		// useful if you use multiple keys for your application.  The standard is to use 'kid' in the
		// head of the token to identify which key to use, but the parsed token (head and claims) is provided
		// to the callback, providing flexibility.
		secret := []byte(tempIdsMiddleware.authServerJwtSecret)
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Validate the alg is what you expect:
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return secret, nil
		})
		if err != nil {
			log.Println("JWT error:", err.Error())
			// c.AbortWithStatus(http.StatusUnauthorized)
			// return
		} else {
			if claims, ok := token.Claims.(jwt.MapClaims); err == nil && ok && token.Valid {
				log.Println(claims["exp"])
				userNameError := false
				accountIdError := false
				userName, err := getUserId(tokenString, tempIdsMiddleware.authServerJwtSecret)
				if err != nil {
					userNameError = true
				} else {
					c.Set("userId", userName)
				}
				accountId, err := getAccountId(tokenString, tempIdsMiddleware.authServerJwtSecret)
				if err != nil {
					accountIdError = true
				} else {
					c.Set("accountId", accountId)
				}
				if !userNameError && !accountIdError {
					authenticated = true
					c.Set("tokenType", "external")
					log.Println("user authenticated with jwt")
					c.Next()
				} else if userNameError && !accountIdError {
					authenticated = true
					c.Set("tokenType", "internal")
					log.Println("user authenticated with jwt")
					c.Next()
				}
				// end of JWT middleware
			}
		}

		if !authenticated {

			// start ids middleware

			method := http.MethodPost
			url := fmt.Sprintf("%s/oauth2/introspect", tempIdsMiddleware.adminUrl)
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
				log.Println("IDS authentication error:", err.Error())
				c.AbortWithStatus(http.StatusUnauthorized)
				return
			}
			var introspectResponse map[string]interface{}
			err = json.Unmarshal(out, &introspectResponse)
			if err != nil {
				err = errors.New("can't unmarshal response")
				log.Println("IDS authentication error:", err.Error())
				c.AbortWithStatus(http.StatusInternalServerError)
				return
			}
			// check validity of access token
			if !introspectResponse["active"].(bool) {
				err = errors.New("access token is invalid/expired")
				log.Println("IDS authentication error:", err.Error())
				c.AbortWithStatus(http.StatusUnauthorized)
				return
			}

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
					log.Println("IDS authentication error:", err.Error())
					c.AbortWithStatus(http.StatusBadRequest)
					return
				}

				accountId, err := utils.GetAccountId(idToken, tempIdsMiddleware.jwksUrl)
				if err != nil {
					log.Println("IDS authentication error:", err.Error())
					c.AbortWithStatus(http.StatusUnauthorized)
					return
				}
				c.Set("accountId", accountId)

				userId, err := utils.GetUserId(idToken, tempIdsMiddleware.jwksUrl)
				if err != nil {
					log.Println("IDS authentication error:", err.Error())
					c.AbortWithStatus(http.StatusUnauthorized)
					return
				}
				c.Set("userId", userId)

				plan, err := utils.GetPlan(idToken, tempIdsMiddleware.jwksUrl)
				if err != nil {
					log.Println("IDS authentication error:", err.Error())
					c.AbortWithStatus(http.StatusUnauthorized)
					return
				}
				c.Set("plan", plan)

				role, err := utils.GetRole(idToken, tempIdsMiddleware.jwksUrl)
				if err != nil && err.Error() != "claim not found" {
					log.Println("IDS authentication error:", err.Error())
					c.AbortWithStatus(http.StatusUnauthorized)
					return
				}
				if err == nil {
					c.Set("role", role)
				} else {
					c.Set("role", "")
				}
			}
			log.Println("user authenticated with ids token")
			c.Next()
		}

	}

}

func getAccountId(tokenString, authServerJwtSecret string) (string, error) {
	claims, err := getClaims(tokenString, authServerJwtSecret)
	if err != nil {
		return "", err
	}
	if user, ok := claims["user"]; ok {
		if userMap, isUserMap := user.(map[string]interface{}); isUserMap {
			if accountId, hasAccountId := userMap["accountId"]; hasAccountId {
				if accountIdString, isAccountIdString := accountId.(string); isAccountIdString {
					return accountIdString, nil
				}
			}
		}
	}
	return "", errors.New("Claim not found")
}

func getUserId(tokenString, authServerJwtSecret string) (string, error) {
	claims, err := getClaims(tokenString, authServerJwtSecret)
	if err != nil {
		return "", err
	}
	if user, ok := claims["user"]; ok {
		if userMap, isUserMap := user.(map[string]interface{}); isUserMap {
			if accountId, hasAccountId := userMap["username"]; hasAccountId {
				if accountIdString, isAccountIdString := accountId.(string); isAccountIdString {
					return accountIdString, nil
				}
			}
		}
	}
	return "", errors.New("Claim not found")
}

func getClaims(tokenString, authServerJwtSecret string) (jwt.MapClaims, error) {
	secret := []byte(authServerJwtSecret)

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("Invalid signature")
		}
		return secret, nil
	})
	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	} else {
		return nil, errors.New("Invalid token")
	}

}
