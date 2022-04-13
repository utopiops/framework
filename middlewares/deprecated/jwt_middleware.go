package middlewares

/*
func JwtAuthorizationMiddleware() gin.HandlerFunc {
	secret := []byte(authServerJwtSecret)
	return func(c *gin.Context) {

		authHeader := c.Request.Header.Get("Authorization")
		if authHeader == "" {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		tokenString := strings.TrimSpace(strings.SplitN(authHeader, "Bearer", 2)[1])
		// Parse takes the token string and a function for looking up the key. The latter is especially
		// useful if you use multiple keys for your application.  The standard is to use 'kid' in the
		// head of the token to identify which key to use, but the parsed token (head and claims) is provided
		// to the callback, providing flexibility.
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Validate the alg is what you expect:
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return secret, nil
		})
		if err != nil {
			fmt.Println(err.Error())
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			log.Println(claims["exp"])
			c.Set("tokenString", tokenString)
			kind, errKind := utils.GetJwtKind(tokenString, authServerJwtSecret)
			if errKind != nil {
				if kind != "internal" {
					accountId, _ := utils.GetAccountId(tokenString, authServerJwtSecret)
					c.Set("accountId", accountId)
					userName, _ := utils.GetUserId(tokenString, authServerJwtSecret)
					c.Set("userId", userName)
				}
			}
			c.Next()
		} else {
			c.AbortWithStatus(http.StatusUnauthorized)
		}
	}
}
*/
