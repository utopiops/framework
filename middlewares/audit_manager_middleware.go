package middlewares

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"gitlab.com/utopiops-water/framework/utils"
)

const SECRET = "secret"

type AuditManagerRequest struct {
	AccountId string `json:"accountId"`
	Username  string `json:"username"`
	Name      string `json:"name"`
	Source    string `json:"source"`
	Ip        string `json:"ip"`
}

type AuditManagerMiddleware struct {
	url          string
	token        string
	source       string
	idsPublicUrl string
	clientId     string
	clientSecret string
}

func NewAuditMiddleware(url, source, idsPublicUrl, clientId, clientSecret string) *AuditManagerMiddleware {
	return &AuditManagerMiddleware{url: url, source: source, idsPublicUrl: idsPublicUrl, clientId: clientId, clientSecret: clientSecret}
}

func (a *AuditManagerMiddleware) register() error {
	// headers := make(http.Header)
	// headers.Set("secret", SECRET)
	// headers.Set("appname", appName)
	// registerUrl := fmt.Sprintf("%s/%s", coreUrl, "auth/apps/register")
	// registerRequest, _ := http.NewRequest("POST", registerUrl, nil)
	// registerRequest.Header = headers
	// resp, err := http.DefaultClient.Do(registerRequest)
	// if err != nil {
	// 	log.Println(err)
	// 	return err
	// }
	// defer resp.Body.Close()
	// if resp.StatusCode != http.StatusOK {
	// 	registerError := fmt.Errorf("failed to register app %s with status %s", appName, resp.Status)
	// 	log.Println(registerError)
	// 	return registerError
	// }
	// getTokenUrl := fmt.Sprintf("%s/%s", coreUrl, "auth/apps/token")
	// getTokenRequest, _ := http.NewRequest("POST", getTokenUrl, nil)
	// getTokenRequest.Header = headers
	// resp1, err := http.DefaultClient.Do(getTokenRequest)
	// if err != nil {
	// 	log.Println(err)
	// 	return err
	// }
	// defer resp1.Body.Close()
	// if resp1.StatusCode != http.StatusOK {
	// 	getTokenError := fmt.Errorf("get token for app %s failed with status %s", appName, resp1.Status)
	// 	log.Println(getTokenError)
	// 	return getTokenError
	// }
	// var tokenDto struct {
	// 	Token string `json:"token"`
	// }
	// bytes, _ := ioutil.ReadAll(resp1.Body)
	// _ = json.Unmarshal(bytes, &tokenDto)
	// a.token = tokenDto.Token
	// log.Printf("app %s registered successfully", appName)
	// return nil
	var err error
	var token string
	for i := 0; i < 5; i++ {
		token, _, err = utils.GetIdsInternalAccessToken(utils.NewHttpHelper(utils.NewHttpClient()), a.idsPublicUrl, a.clientId, a.clientSecret)
		if err == nil {
			break
		}
	}
	a.token = token
	return err
}

func (a *AuditManagerMiddleware) Audit(event string) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		tokenType := ctx.MustGet("tokenType").(string)
		if tokenType == "internal" {
			ctx.Next()
			return
		}
		accountId := ctx.MustGet("accountId").(string)
		username := ctx.MustGet("userId").(string)
		ip := ctx.ClientIP()
		body := AuditManagerRequest{
			AccountId: accountId,
			Username:  username,
			Name:      event,
			Source:    appName,
			Ip:        ip,
		}
		data, _ := json.Marshal(body)
		status, err := doReq(data, a.token, a.url)
		if err != nil {
			log.Println(err)
			ctx.Status(http.StatusInternalServerError)
			return
		}
		if status == http.StatusUnauthorized {
			err = a.register()
			if err != nil {
				log.Println("failed to register app")
				ctx.Status(http.StatusInternalServerError)
				return
			}
			status, err = doReq(data, a.token, a.url)
		}
		if status != http.StatusOK {
			log.Printf("for event %v status is: %d", string(data), status)
			ctx.Status(status)
			return
		}
		ctx.Next()
	}
}

func doReq(data []byte, token, url string) (int, error) {
	req, _ := http.NewRequest("POST", url, bytes.NewBuffer(data))
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Println(err)
		return -1, err
	}
	defer resp.Body.Close()
	return resp.StatusCode, nil
}
