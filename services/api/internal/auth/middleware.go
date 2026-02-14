package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type contextKey string

const (
	ClaimsKey contextKey = "claims"
)

type Claims struct {
	Sub           string   `json:"sub"`
	Email         string   `json:"email"`
	RealmRoles    []string `json:"realm_roles"`
	PreferredUser string   `json:"preferred_username"`
}

func Middleware(keycloakURL, realm string) func(http.Handler) http.Handler {
	jwksURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/certs", keycloakURL, realm)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, `{"error":"missing authorization header"}`, http.StatusUnauthorized)
				return
			}

			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
				http.Error(w, `{"error":"invalid authorization format"}`, http.StatusUnauthorized)
				return
			}

			tokenStr := parts[1]

			token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
					return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
				}
				kid, ok := token.Header["kid"].(string)
				if !ok {
					return nil, fmt.Errorf("missing kid in token header")
				}
				return fetchPublicKey(jwksURL, kid)
			})

			if err != nil || !token.Valid {
				http.Error(w, `{"error":"invalid token"}`, http.StatusUnauthorized)
				return
			}

			mapClaims, ok := token.Claims.(jwt.MapClaims)
			if !ok {
				http.Error(w, `{"error":"invalid claims"}`, http.StatusUnauthorized)
				return
			}

			claims := extractClaims(mapClaims)
			ctx := context.WithValue(r.Context(), ClaimsKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func extractClaims(m jwt.MapClaims) *Claims {
	c := &Claims{}
	if sub, ok := m["sub"].(string); ok {
		c.Sub = sub
	}
	if email, ok := m["email"].(string); ok {
		c.Email = email
	}
	if username, ok := m["preferred_username"].(string); ok {
		c.PreferredUser = username
	}
	if access, ok := m["realm_access"].(map[string]interface{}); ok {
		if roles, ok := access["roles"].([]interface{}); ok {
			for _, r := range roles {
				if role, ok := r.(string); ok {
					c.RealmRoles = append(c.RealmRoles, role)
				}
			}
		}
	}
	return c
}

func GetClaims(r *http.Request) *Claims {
	claims, _ := r.Context().Value(ClaimsKey).(*Claims)
	return claims
}

var httpClient = &http.Client{Timeout: 10 * time.Second}

func fetchPublicKey(jwksURL, kid string) (interface{}, error) {
	resp, err := httpClient.Get(jwksURL)
	if err != nil {
		return nil, fmt.Errorf("fetch jwks: %w", err)
	}
	defer resp.Body.Close()

	var jwks struct {
		Keys []struct {
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
			Kty string `json:"kty"`
		} `json:"keys"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("decode jwks: %w", err)
	}

	for _, key := range jwks.Keys {
		if key.Kid == kid {
			return jwt.ParseRSAPublicKeyFromPEM([]byte(fmt.Sprintf(
				"-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----",
				key.N,
			)))
		}
	}

	return nil, fmt.Errorf("key %s not found", kid)
}
