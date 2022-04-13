package middlewares

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/utopiops/framework/models"
	"github.com/utopiops/framework/utils"
)

const (
	accessManagerRequestTimeLimit time.Duration = 10 * time.Second
)

type AccessManagerRequest struct {
	UserID   string `json:"userId"`
	Resource string `json:"resource"`
	Action   string `json:"action"`
}
type AccessManagerResponse struct {
	Allowed bool `json:"allowed"`
}

func Authorize(resource, action string, params ...models.AuthorizeResource) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.Request.Header.Get("Authorization")
		// tokenString := strings.TrimSpace(strings.SplitN(authHeader, "Bearer", 2)[1])
		kind, exists := c.Get("tokenType")
		if !exists {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		if kind == "internal" {
			c.Next()
			return
		}
		resourceString, err := setResourceString(c, resource, params)
		if err != nil {
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}
		userId, exists := c.Get("userId")
		if !exists {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		httpHelper := utils.NewHttpHelper(utils.NewHttpClient())
		url := fmt.Sprintf("%s/policy/enforce", accessManagerUrl)
		headers := []utils.Header{
			{
				Key:   "Authorization",
				Value: authHeader,
			},
		}
		idToken, err := c.Cookie("id_token")
		/*if err != nil {
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}*/
		if err == nil {
			headers = append(headers, utils.Header{
				Key:   "Cookie",
				Value: fmt.Sprintf("id_token=%s", idToken),
			})
		}
		data := AccessManagerRequest{
			UserID:   userId.(string),
			Resource: resourceString,
			Action:   action,
		}
		json_data, err := json.Marshal(data)
		if err != nil {
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}
		body := bytes.NewBuffer(json_data)
		log.Print(fmt.Sprintf("sending request for Authorization to %s with body: ", url))
		log.Println(data)
		response, err, status, _ := httpHelper.HttpRequest(http.MethodPost, url, body, headers, accessManagerRequestTimeLimit)
		if err != nil || status != http.StatusOK {
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		var res AccessManagerResponse
		if err := json.Unmarshal(response, &res); err != nil {
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		if res.Allowed {
			c.Next()
			return
		}
		c.AbortWithStatus(http.StatusForbidden)
	}
}

func setResourceString(c *gin.Context, startingPoint string, params []models.AuthorizeResource) (string, error) {
	var body map[string]interface{}
	resource := fmt.Sprintf("%s::%s", appName, startingPoint)
	for _, param := range params {
		var value string
		if param.Type == "param" {
			value = c.Param(param.Key)
		} else if param.Type == "query" {
			value = c.Query(param.Key)
		} else if param.Type == "body" {
			if body == nil {
				if err := c.ShouldBindQuery(&body); err != nil {
					return "", err
				}
			}
			tmp, ok := body[param.Key]
			if !ok {
				return "", errors.New("value not found in body")
			}
			value = tmp.(string)
		}
		resource += "/" + value
	}
	return resource, nil
}
