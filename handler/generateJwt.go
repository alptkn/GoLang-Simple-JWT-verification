package handler

import (
	"encoding/json"
	"fmt"
	"jwt-example/configs"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt"
)

type Message struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

var users = map[string]string{
	"user1": "password1",
	"user2": "password2",
	"user3": "password3",
}

func SignIn(writer http.ResponseWriter, request *http.Request) {

	writer.Header().Set("Content-Type", "application/json")
	var creds Credentials

	err := json.NewDecoder(request.Body).Decode(&creds)
	if err != nil {
		writer.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(writer).Encode(Message{"error", "Invalid request payload"})
		return
	}

	password, ok := users[creds.Username]

	if !ok || password != creds.Password {
		writer.WriteHeader(http.StatusUnauthorized)
		return
	}

	claims := Claims{
		Username: creds.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Minute * 3).Unix(),
		},
	}

	token, err := GenerateJWT(claims)

	if err != nil {
		writer.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(writer).Encode(Message{"error", "Error signing token"})
		return
	}

	http.SetCookie(writer, &http.Cookie{
		Name:    "token",
		Value:   token,
		Expires: time.Now().Add(time.Minute * 3),
	})

}

func WellCome(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Content-Type", "application/json")
	c, err := request.Cookie("token")
	if err != nil {
		if err == http.ErrNoCookie {
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		writer.WriteHeader(http.StatusBadRequest)
		return
	}

	claims := &Claims{}

	token, err := jwt.ParseWithClaims(c.Value, claims, func(token *jwt.Token) (interface{}, error) {
		_, ok := token.Method.(*jwt.SigningMethodHMAC)
		if !ok {

			return nil, nil
		}
		return []byte(configs.Configs.SecretKey), nil
	})

	if err != nil {
		writer.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(writer).Encode(Message{"error", "Invalid token"})
		return
	}

	if !token.Valid {
		writer.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(writer).Encode(Message{"error", "Invalid token"})
		return
	}
	writer.Write([]byte(fmt.Sprintf("Welcome %s!", claims.Username)))
}

func GenerateJWT(claims Claims) (string, error) {

	configs.LoadConfigs()
	config := configs.Configs

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenStr, err := token.SignedString([]byte(config.SecretKey))

	if err != nil {
		return "", err
	}

	return tokenStr, nil
}

func RefreshToken(writer http.ResponseWriter, request *http.Request) {

	c, err := request.Cookie("token")
	if err != nil {
		if err == http.ErrNoCookie {
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}

		fmt.Print("Err:", err)
		writer.WriteHeader(http.StatusBadRequest)
		return
	}

	tokenStr := c.Value
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		_, ok := token.Method.(*jwt.SigningMethodHMAC)

		if !ok {

			return nil, nil
		}

		return []byte(configs.Configs.SecretKey), nil
	})

	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		fmt.Print("Err:", err)
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	if !token.Valid {
		writer.WriteHeader(http.StatusUnauthorized)
		return
	}

	currentTokenExpireAt := time.Unix(claims.ExpiresAt, 0)

	fmt.Print("Old expiry date: ", currentTokenExpireAt, "\n")
	fmt.Print("Now: ", time.Now(), "\n")

	if time.Until(currentTokenExpireAt) > 30*time.Second {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}

	newExpireAt := time.Now().Add(time.Minute * 3)

	claims.ExpiresAt = newExpireAt.Unix()
	newToken, err := GenerateJWT(*claims)

	if err != nil {
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}

	http.SetCookie(writer, &http.Cookie{
		Name:    "token",
		Value:   newToken,
		Expires: newExpireAt,
	})

}
