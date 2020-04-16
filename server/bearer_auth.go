package server

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/dgrijalva/jwt-go"
	natsjwt "github.com/nats-io/jwt"
	"golang.org/x/crypto/ssh"
)

type jwtKeypair struct {
	fingerprint string
	publicKey   rsa.PublicKey
	privateKey  *rsa.PrivateKey
}

// BearerAuth references the server and map of available keys for verification
type BearerAuth struct {
	server     *Server
	publicKeys map[string]*jwtKeypair
}

// BearerAuthFactory initializes and configures JWT bearer auth for the given server
func BearerAuthFactory(s *Server) (*BearerAuth, error) {
	auth := &BearerAuth{
		server: s,
	}
	err := auth.requireJWTVerifiers()
	if err != nil {
		return nil, fmt.Errorf("failed to require JWT verifiers")
	}
	return auth, nil
}

func (bearer *BearerAuth) requireJWTVerifiers() error {
	bearer.publicKeys = map[string]*jwtKeypair{}

	jwtPublicKeyPEM := strings.Replace(os.Getenv("JWT_SIGNER_PUBLIC_KEY"), `\n`, "\n", -1)
	publicKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(jwtPublicKeyPEM))
	if err != nil {
		return err
	}

	sshPublicKey, err := ssh.NewPublicKey(publicKey)
	if err != nil {
		return err
	}
	fingerprint := ssh.FingerprintLegacyMD5(sshPublicKey)

	bearer.publicKeys[fingerprint] = &jwtKeypair{
		fingerprint: fingerprint,
		publicKey:   *publicKey,
	}

	return nil
}

func (bearer *BearerAuth) resolveJWTFingerprints() []string {
	fingerprints := make([]string, 0, len(bearer.publicKeys))
	for k := range bearer.publicKeys {
		fingerprints = append(fingerprints, k)
	}
	return fingerprints
}

// resolveJWTKeypair returns the configured public key given its fingerprint
func (bearer *BearerAuth) resolvePublicKey(fingerprint *string) *rsa.PublicKey {
	if bearer.publicKeys == nil || len(bearer.publicKeys) == 0 {
		return nil
	}

	var keypair *jwtKeypair

	if fingerprint == nil {
		keypair = bearer.publicKeys[bearer.resolveJWTFingerprints()[0]]
	} else {
		if jwtKeypair, jwtKeypairOk := bearer.publicKeys[*fingerprint]; jwtKeypairOk {
			keypair = jwtKeypair
		}
	}

	if keypair == nil {
		return nil
	}

	return &keypair.publicKey
}

// Check parses the JWT as a bearer token
func (bearer *BearerAuth) Check(c ClientAuthentication) bool {
	bearerToken := c.GetOpts().JWT
	jwtToken, err := jwt.Parse(bearerToken, func(_jwtToken *jwt.Token) (interface{}, error) {
		if _, ok := _jwtToken.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("failed to parse bearer authorization; unexpected signing alg: %s", _jwtToken.Method.Alg())
		}

		var kid *string
		if kidhdr, ok := _jwtToken.Header["kid"].(string); ok {
			kid = &kidhdr
		}

		publicKey := bearer.resolvePublicKey(kid)
		if publicKey == nil {
			msg := "failed to resolve a valid JWT verification key"
			if kid != nil {
				msg = fmt.Sprintf("%s; invalid kid specified in header: %s", msg, *kid)
			} else {
				msg = fmt.Sprintf("%s; no default verification key configured", msg)
			}
			return nil, fmt.Errorf(msg)
		}

		return publicKey, nil
	})
	if err != nil {
		bearer.server.Debugf(fmt.Sprintf("failed to parse bearer authorization; %s", err.Error()))
		return false
	}

	bearer.server.Debugf(fmt.Sprintf("parsed bearer authorization: %s\n; client authentication: %s", jwtToken.Claims, c))
	claims, claimsOk := jwtToken.Claims.(jwt.MapClaims)
	if !claimsOk {
		bearer.server.Warnf("no claims present in verified JWT; client authentication: %s", c)
		return false
	}

	permissions := &Permissions{}
	if natsClaim, natsClaimOk := claims["nats"].(map[string]interface{}); natsClaimOk {
		if permissionsClaim, permissionsClaimOk := natsClaim["permissions"].(map[string]interface{}); permissionsClaimOk {
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
			if _, allowResponsesOk := permissionsClaim["subscribe"]; !allowResponsesOk {
				permissionsClaim["allow_responses"] = false
			}

			permissionsRaw, _ := json.Marshal(permissionsClaim)
			json.Unmarshal(permissionsRaw, &permissions) // HACK
		} else {
			bearer.server.Warnf(fmt.Sprintf("no permissions claim present in verified JWT; %s", bearerToken))
			return false
		}
	} else {
		bearer.server.Warnf(fmt.Sprintf("no nats claim present in verified JWT; %s", bearerToken))
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
