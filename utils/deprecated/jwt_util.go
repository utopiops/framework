package utils

// authServerJwtSecret is config.Configs.Secrets.AuthServerJwtSecret for each service

/*
func GetAccountId(tokenString, authServerJwtSecret string) (string, error) {
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

func GetUserId(tokenString, authServerJwtSecret string) (string, error) {
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

func GetJwtKind(tokenString, authServerJwtSecret string) (string, error) {
	claims, err := getClaims(tokenString, authServerJwtSecret)
	if err != nil {
		return "", err
	}
	if jwtKind, ok := claims["kind"]; ok {
		kind := jwtKind.(string)
		if kind != "" {
			return kind, nil
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
*/
