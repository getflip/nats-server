package server

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/dgrijalva/jwt-go"
	natsjwt "github.com/nats-io/jwt"
)

type BearerAuth struct {
	server    *Server
	publicKey *rsa.PublicKey
}

func BearerAuthFactory(s *Server) (*BearerAuth, error) {
	auth := &BearerAuth{
		server: s,
	}
	err := auth.readPublicKey()
	if err != nil {
		return nil, fmt.Errorf("failed to read JWT_SIGNER_PUBLIC_KEY from environment")
	}
	return auth, nil
}

func (bearer *BearerAuth) readPublicKey() error {
	jwtPublicKeyPEM := strings.Replace(os.Getenv("JWT_SIGNER_PUBLIC_KEY"), `\n`, "\n", -1)
	publicKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(jwtPublicKeyPEM))
	if err != nil {
		return err
	}
	bearer.publicKey = publicKey
	return nil
}

func (bearer *BearerAuth) Check(c ClientAuthentication) bool {
	bearerToken := c.GetOpts().JWT
	jwtToken, err := jwt.Parse(bearerToken, func(_jwtToken *jwt.Token) (interface{}, error) {
		if _, ok := _jwtToken.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("failed to parse bearer authorization; unexpected signing alg: %s", _jwtToken.Method.Alg())
		}
		return bearer.publicKey, nil
	})
	if err != nil {
		bearer.server.Debugf(fmt.Sprintf("failed to parse bearer authorization; %s", err.Error()))
		return false
	}

	bearer.server.Debugf(fmt.Sprintf("parsed bearer authorization: %s\n; client authentication: %s", jwtToken.Claims, c))
	claims, claimsOk := jwtToken.Claims.(jwt.MapClaims)
	if !claimsOk {
		bearer.server.Warnf(fmt.Sprintf("no claims present in verified JWT; %s", err.Error()))
		return false
	}

	permissions := &Permissions{}
	if permissionsClaim, permissionsClaimOk := claims["permissions"].(map[string]interface{}); permissionsClaimOk {
		if _, pubOk := permissionsClaim["publish"]; !pubOk {
			permissionsClaim["publish"] = map[string]interface{}{
				"allow": []string{},
				"deny":  []string{},
			}
		}
		if _, subOk := permissionsClaim["subscribe"]; !subOk {
			permissionsClaim["subscribe"] = map[string]interface{}{
				"allow": []string{},
				"deny":  []string{},
			}
		}
		if _, respOk := permissionsClaim["responses"]; !respOk {
			permissionsClaim["responses"] = map[string]interface{}{
				"max": DEFAULT_ALLOW_RESPONSE_MAX_MSGS,
				"ttl": DEFAULT_ALLOW_RESPONSE_EXPIRATION,
			}
		}
		permissionsRaw, _ := json.Marshal(permissionsClaim)
		json.Unmarshal(permissionsRaw, &permissions) // HACK
	} else {
		bearer.server.Warnf(fmt.Sprintf("no permissions claim present in verified JWT; %s", bearerToken))
		return false
	}

	bearer.server.Debugf("registering user with permissions: %s", permissions)
	c.RegisterUser(&User{
		Permissions: permissions,
	})

	if cl, clOk := c.(*client); clOk {
		var exp int64
		switch expClaim := claims["exp"].(type) {
		case float64:
			exp = int64(expClaim)
		case json.Number:
			exp, _ = expClaim.Int64()
		default:
			bearer.server.Debugf("failed to parse bearer authorization expiration")
			return false
		}

		bearer.server.Debugf("enforcing authorized expiration: %v", exp)
		cl.checkExpiration(&natsjwt.ClaimsData{
			Expires: exp,
		})
	}
	return true
}
