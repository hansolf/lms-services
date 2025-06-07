package middleware

import (
	"context"
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"net/http"
	"os"
)

func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("token")
		if err != nil {
			http.Error(w, "Не авторизован", http.StatusUnauthorized)
			return
		}
		token, err := jwt.Parse(cookie.Value, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(os.Getenv("SECRET")), nil
		})
		if err != nil || !token.Valid {
			http.Error(w, "Неверный токен", http.StatusUnauthorized)
			return
		}
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			http.Error(w, "Ошибка claims", http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), "claims", claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

type UserInfo struct {
	ID       string `json:"id"`
	Name     string `json:"username"`
	Surname  string `json:"surname"`
	Email    string `json:"email"`
	Role     string `json:"role"`
	Vuz      string `json:"vuz"`
	Kafedra  string `json:"kafedra"`
	Fakultet string `json:"fakultet"`
}

func GetUserInfoFromContext(r *http.Request) (UserInfo, bool) {
	claims, ok := r.Context().Value("claims").(jwt.MapClaims)
	if !ok {
		return UserInfo{}, false
	}
	user := UserInfo{
		ID:       fmt.Sprintf("%v", claims["sub"]),
		Name:     fmt.Sprintf("%v", claims["name"]),
		Surname:  fmt.Sprintf("%v", claims["surname"]),
		Email:    fmt.Sprintf("%v", claims["email"]),
		Role:     fmt.Sprintf("%v", claims["role"]),
		Vuz:      fmt.Sprintf("%v", claims["vuz"]),
		Kafedra:  fmt.Sprintf("%v", claims["kafedra"]),
		Fakultet: fmt.Sprintf("%v", claims["fakultet"]),
	}
	return user, true
}
