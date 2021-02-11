package main

import (
	"context"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"net/http"
	"strings"
)

var secret []byte = []byte("notReallyASecret")

func JWTmiddleware(next func(http.ResponseWriter, *http.Request)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		authHeaderSplit := strings.Split(req.Header.Get("Authorization"), " ")
		if len(authHeaderSplit) != 2 {
			fmt.Println("Couldn't authorize with JWT. Received malformed Authorization header value\n")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		tokenStr := authHeaderSplit[1]

		token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v\n\n", token.Header["alg"])
			}
			return secret, nil
		})
		if err != nil {
			fmt.Println("Error parsing JWT:", err, "\n")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		if claims := token.Claims; token.Valid {
			fmt.Println("Authorized with JWT middleware\n")
			next(w, req.WithContext(context.WithValue(req.Context(), "props", claims)))
		} else {
			fmt.Println("Couldn't authorize with JWT. JWTs are not the same\n")
			w.WriteHeader(http.StatusUnauthorized)
		}
	})
}
