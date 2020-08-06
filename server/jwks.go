package server

import (
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/dgrijalva/jwt-go"
	"github.com/lestrrat/go-jwx/jwk"
)

type Keycloak struct {
	server    *Server
	host      string
	jwksCache map[string]*jwk.Set
}

var once sync.Once
var keycloak *Keycloak

func KeycloakInstance(server *Server) *Keycloak {
	once.Do(func() {
		keycloak = new(Keycloak)
		keycloak.server = server
		keycloak.host = keycloakHost()
		keycloak.jwksCache = make(map[string]*jwk.Set)
	})
	return keycloak
}
func keycloakHost() string {
	return os.Getenv("KEYCLOAK_HOST")
}
func (keycloak *Keycloak) PublicKey(token *jwt.Token) (interface{}, error) {
	return keycloak.publicKey(token, true)
}

func (keycloak *Keycloak) publicKey(token *jwt.Token, retry bool) (interface{}, error) {
	keyID, ok := token.Header["kid"].(string)
	if !ok {
		return nil, errors.New("expecting JWT header to have string kid")
	}

	claims := token.Claims.(jwt.MapClaims)
	realm := claims["tenant"]
	keycloak.server.Debugf("Verifying token for tenant '%s'\n", realm)

	jwksURL := fmt.Sprintf("http://%s/auth/realms/%s/protocol/openid-connect/certs", keycloak.host, realm)
	jwks, exists := keycloak.jwksCache[jwksURL]
	if exists {
		keycloak.server.Debugf("Using JWKS from cache (realm '%s')\n", realm)
	} else {
		keycloak.server.Debugf("Fetching JWKS (realm '%s')\n", realm)
		jwksFetch, err := jwk.FetchHTTP(jwksURL)
		if err != nil {
			return nil, err
		}
		jwks = jwksFetch
		keycloak.jwksCache[jwksURL] = jwks
	}

	if key := jwks.LookupKeyID(keyID); len(key) == 1 {
		return key[0].Materialize()
	} else {
		if retry {
			// current jwks does not match the tokens kid, the servers jwks might have changed
			keycloak.server.Warnf("JWKS (realm '%s') doesn't match given token, trying to refetch jwks", realm)
			delete(keycloak.jwksCache, jwksURL)
			return keycloak.publicKey(token, false)
		} else {
			keycloak.server.Errorf("Newly fetched JWKS (realm '%s') doesn't match given token, giving up", realm)
			return nil, errors.New("Unable to find public key for JKWS url '" + jwksURL + "'")
		}
	}
}
