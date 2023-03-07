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
	mutex     *sync.Mutex
}

var once sync.Once
var keycloak *Keycloak

func KeycloakInstance(server *Server) *Keycloak {
	once.Do(func() {
		keycloak = new(Keycloak)
		keycloak.server = server
		keycloak.host = keycloakHost()
		keycloak.jwksCache = make(map[string]*jwk.Set)
		keycloak.mutex = &sync.Mutex{}
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
	keycloak.server.Debugf("Verifying token for tenant '%s'", realm)

	jwksURL := fmt.Sprintf("http://%s/auth/realms/%s/protocol/openid-connect/certs", keycloak.host, realm)

	keycloak.mutex.Lock()
	jwks, exists := keycloak.jwksCache[jwksURL]
	keycloak.mutex.Unlock()

	if exists {
		keycloak.server.Debugf("Using JWKS from cache (realm '%s')", realm)
	} else {
		keycloak.server.Debugf("Fetching JWKS (realm '%s')", realm)
		jwksFetch, err := jwk.FetchHTTP(jwksURL)
		if err != nil {
			keycloak.server.Errorf("Failed to fetch JWKS for realm '%s' from %s", realm, jwksURL)
			return nil, err
		}
		jwks = jwksFetch
		keycloak.mutex.Lock()
		keycloak.jwksCache[jwksURL] = jwks
		keycloak.mutex.Unlock()
	}

	if key := jwks.LookupKeyID(keyID); len(key) == 1 {
		return key[0].Materialize()
	} else {
		if retry {
			// current jwks does not match the tokens kid, the servers jwks might have changed
			keycloak.server.Warnf("JWKS (realm '%s') doesn't match given token, trying to refetch jwks", realm)
			keycloak.mutex.Lock()
			delete(keycloak.jwksCache, jwksURL)
			keycloak.mutex.Unlock()
			return keycloak.publicKey(token, false)
		} else {
			keycloak.server.Errorf("Newly fetched JWKS (realm '%s') doesn't match given token, giving up", realm)
			return nil, errors.New("Unable to find public key for JKWS url '" + jwksURL + "'")
		}
	}
}
