package middlewares

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

type PlanManagerRequest struct {
	Resource string `json:"resource"`
	Action   string `json:"action"`
}

type PlanManagerResponse struct {
	Allowed bool `json:"allowed"`
}

type PlanManagerMiddleware struct {
	url string
}

func NewPlanManagerMiddleware(url string) *PlanManagerMiddleware {
	return &PlanManagerMiddleware{
		url: url,
	}
}

func (p *PlanManagerMiddleware) Access(resource, action string) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		tokenType := ctx.MustGet("tokenType").(string)
		if tokenType == "internal" {
			ctx.Next()
			return
		}
		body := PlanManagerRequest{
			Resource: resource,
			Action:   action,
		}
		data, _ := json.Marshal(body)
		url := fmt.Sprintf("%s/user/enforce", p.url)
		req, _ := http.NewRequest("POST", url, bytes.NewReader(data))
		req.Header = ctx.Request.Header
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			log.Println(err)
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
				"error": err.Error(),
			})
			return
		}
		if resp.StatusCode != http.StatusOK {
			err = fmt.Errorf("plan manager request failed with status %d", resp.StatusCode)
			log.Println(err)
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
				"error": err.Error(),
			})
			return
		}
		respBody, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Println(err)
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
				"error": err.Error(),
			})
			return
		}
		var response PlanManagerResponse
		if err := json.Unmarshal(respBody, &response); err != nil {
			log.Println(err)
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
				"error": err.Error(),
			})
			return
		}
		if response.Allowed {
			ctx.Next()
			return
		}
		ctx.AbortWithStatus(http.StatusForbidden)
	}
}
