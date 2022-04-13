package utils

import (
	"context"
	"errors"
	"fmt"

	"github.com/dgrijalva/jwt-go"
	"github.com/lestrrat-go/jwx/jwk"
)

// idsJwksUrl is config.Configs.Endpoints.idsJwksUrl for each service

func GetUserId(tokenString, idsJwksUrl string) (string, error) {
	claims, err := getIdTokenClaims(tokenString, idsJwksUrl)
	if err != nil {
		return "", err
	}
	if userId, ok := claims["sub"]; ok {
		userIdString := userId.(string)
		if userIdString != "" {
			return userIdString, nil
		}
	}
	return "", errors.New("claim not found")
}

func GetAccountId(tokenString, idsJwksUrl string) (string, error) {
	claims, err := getIdTokenClaims(tokenString, idsJwksUrl)
	if err != nil {
		return "", err
	}
	if accountId, ok := claims["account_id"]; ok {
		accountIdString := accountId.(string)
		if accountIdString != "" {
			return accountIdString, nil
		}
	}
	return "", errors.New("claim not found")
}

func GetPlan(tokenString, idsJwksUrl string) (string, error) {
	claims, err := getIdTokenClaims(tokenString, idsJwksUrl)
	if err != nil {
		return "", err
	}
	if accountId, ok := claims["plan"]; ok {
		accountIdString := accountId.(string)
		if accountIdString != "" {
			return accountIdString, nil
		}
	}
	return "", errors.New("claim not found")
}

func GetRole(tokenString, idsJwksUrl string) (string, error) {
	claims, err := getIdTokenClaims(tokenString, idsJwksUrl)
	if err != nil {
		return "", err
	}
	if accountId, ok := claims["role"]; ok {
		accountIdString := accountId.(string)
		if accountIdString != "" {
			return accountIdString, nil
		}
	}
	return "", errors.New("claim not found")
}

func getIdTokenClaims(tokenString, idsJwksUrl string) (jwt.MapClaims, error) {

	tok, err := jwt.Parse(tokenString, func(jwtToken *jwt.Token) (interface{}, error) {
		set, err := jwk.Fetch(context.Background(), idsJwksUrl)
		if err != nil {
			return nil, err
		}

		keyID, ok := jwtToken.Header["kid"].(string)
		if !ok {
			return nil, errors.New("expecting JWT header to have string kid")
		}

		if key, ok := set.LookupKeyID(keyID); ok {
			var pubkey interface{}
			err := key.Raw(&pubkey)
			return pubkey, err
		}

		return nil, fmt.Errorf("unable to find key %q", keyID)
	})
	if err != nil {
		return nil, fmt.Errorf("validate: %w", err)
	}

	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok || !tok.Valid {
		return nil, fmt.Errorf("validate: invalid")
	}
	return claims, nil
}
