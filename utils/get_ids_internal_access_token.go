package utils

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

func GetIdsInternalAccessToken(httpHelper HttpHelper, idsPublicUrl, clientId, clientSecret string) (accessToken, tokenType string, err error) {
	method := http.MethodPost
	url := fmt.Sprintf("%s/oauth2/token", idsPublicUrl)
	encodedClientInfo := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", clientId, clientSecret)))
	accessTokenHeaders := []Header{
		{
			Key:   "Authorization",
			Value: "Basic " + encodedClientInfo,
		},
		{
			Key:   "Content-Type",
			Value: "application/x-www-form-urlencoded",
		},
	}
	// send a POST request to ids public to get an access token (client credentials flow)
	out, err, statusCode, _ := httpHelper.HttpRequest(method, url, bytes.NewBuffer([]byte("grant_type=client_credentials")), accessTokenHeaders, 0)
	if err != nil || statusCode != http.StatusOK {
		err = errors.New("can't get correct response from identity server")
		return
	}
	var accessTokenResponse map[string]interface{}
	err = json.Unmarshal(out, &accessTokenResponse)
	if err != nil {
		err = errors.New("can't unmarshal response")
		return
	}
	accessToken = accessTokenResponse["access_token"].(string)
	tokenType = accessTokenResponse["token_type"].(string)
	return
}
