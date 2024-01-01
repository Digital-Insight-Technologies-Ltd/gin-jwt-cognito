package jwt

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	jwtgo "github.com/golang-jwt/jwt/v5"
	"github.com/sirupsen/logrus"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"
)

var AuthHeaderEmptyError = errors.New("HTTP authorization header empty")

const (

	// AuthenticateHeader the Gin authenticate header
	AuthenticateHeader = "WWW-Authenticate"

	// AuthorizationHeader the auth header that gets passed to all services
	AuthorizationHeader = "Authorization"

	// HEADER used by the JWT middle ware
	HEADER = "header"

	// IssuerFieldName the issuer field name
	IssuerFieldName = "iss"
)

// AuthMiddleware middleware
type AuthMiddleware struct {

	// User can define own Unauthorized func.
	Unauthorized func(*gin.Context, int, string)

	Timeout time.Duration

	// TokenLookup the header name of the token
	TokenLookup string

	// TimeFunc
	TimeFunc func() time.Time

	// Realm name to display to the user. Required.
	Realm string

	// to verify issuer
	VerifyIssuer bool

	// Region aws region
	Region string

	// UserPoolID the cognito user pool id
	UserPoolID string

	// The issuer
	Iss string

	// JWK public JSON Web Key (JWK) for your user pool
	JWK map[string]JWKKey

	// Allowed Client Ids
	AllowedClientIds []string
}

// JWK is json data struct for JSON Web Key
type JWK struct {
	Keys []JWKKey
}

// JWKKey is json data struct for cognito jwk key
type JWKKey struct {
	Alg string
	E   string
	Kid string
	Kty string
	N   string
	Use string
}

// AuthError auth error response
type AuthError struct {
	Code    int `json:"code"`
	Message any `json:"message"`
}

// MiddlewareInit initialize jwt configs.
func (mw *AuthMiddleware) MiddlewareInit() {

	if mw.TokenLookup == "" {
		mw.TokenLookup = "header:" + AuthorizationHeader
	}

	if mw.Timeout == 0 {
		mw.Timeout = time.Hour
	}

	if mw.TimeFunc == nil {
		mw.TimeFunc = time.Now
	}

	if mw.Unauthorized == nil {
		mw.Unauthorized = func(c *gin.Context, code int, message string) {
			c.JSON(code, AuthError{Code: code, Message: message})
		}
	}

	if mw.Realm == "" {
		mw.Realm = "gin jwt"
	}
}

func (mw *AuthMiddleware) middlewareImpl(c *gin.Context) {

	// Parse the given token
	var tokenStr string
	var err error

	parts := strings.Split(mw.TokenLookup, ":")

	switch parts[0] {
	case HEADER:
		tokenStr, err = mw.jwtFromHeader(c, parts[1])
	}

	if err != nil {
		logrus.Errorf("Unable to authenticate: %v", err.Error())
		mw.unauthorized(c, http.StatusUnauthorized, err.Error())
		return
	}

	// Info.Printf("tokenStr: %v", tokenStr)

	token, err := mw.parse(tokenStr)

	if err != nil {
		logrus.Errorf("JWT token Parser error: %s", err.Error())
		mw.unauthorized(c, http.StatusUnauthorized, err.Error())
		return
	}

	c.Set("JWT_TOKEN", token)
	c.Next()
}

func (mw *AuthMiddleware) jwtFromHeader(c *gin.Context, key string) (string, error) {
	authHeader := c.Request.Header.Get(key)

	if authHeader == "" {
		return "", AuthHeaderEmptyError
	}
	return authHeader, nil
}

func (mw *AuthMiddleware) unauthorized(c *gin.Context, code int, message string) {
	if mw.Realm == "" {
		mw.Realm = "gin jwt"
	}
	c.Header(AuthenticateHeader, "JWT realm="+mw.Realm)
	c.Abort()

	mw.Unauthorized(c, code, message)
	return
}

// MiddlewareFunc implements the Middleware interface.
func (mw *AuthMiddleware) MiddlewareFunc() gin.HandlerFunc {
	// initialise
	mw.MiddlewareInit()
	return func(c *gin.Context) {
		mw.middlewareImpl(c)
		return
	}
}

// AuthJWTMiddleware create an instance of the middle ware function
//
//goland:noinspection GoUnusedExportedFunction
func AuthJWTMiddleware(iss, userPoolID, region string, allowedClientIds []string) (*AuthMiddleware, error) {

	// Download the public json web key for the given user pool ID at the start of the plugin
	jwk, err := getJWK(fmt.Sprintf("https://cognito-idp.%v.amazonaws.com/%v/.well-known/jwks.json", region, userPoolID))
	if err != nil {
		return nil, err
	}

	authMiddleware := &AuthMiddleware{
		Timeout: time.Hour,

		Unauthorized: func(c *gin.Context, code int, message string) {
			c.JSON(code, AuthError{Code: code, Message: message})
		},

		// Token header
		TokenLookup:      "header:" + AuthorizationHeader,
		TimeFunc:         time.Now,
		JWK:              jwk,
		Iss:              iss,
		Region:           region,
		UserPoolID:       userPoolID,
		AllowedClientIds: allowedClientIds,
	}

	return authMiddleware, nil
}

func (mw *AuthMiddleware) parse(tokenStr string) (*jwtgo.Token, error) {

	// 0. remove "Bearer " from the tokenStr
	tokenStr = strings.Split(tokenStr, "Bearer ")[1]

	// 1. Decode the token string into JWT format.
	token, err := jwtgo.Parse(tokenStr, func(token *jwtgo.Token) (interface{}, error) {

		// cognito user pool : RS256
		if _, ok := token.Method.(*jwtgo.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// 5. Get the kid from the JWT token header and retrieve the corresponding JSON Web Key that was stored
		if kid, ok := token.Header["kid"]; ok {
			if kidStr, ok := kid.(string); ok {
				key := mw.JWK[kidStr]
				// 6. Verify the signature of the decoded JWT token.
				rsaPublicKey := convertKey(key.E, key.N)
				return rsaPublicKey, nil
			}
		}

		// rsa public key
		return "", nil
	})

	if err != nil {
		return token, err
	}

	claims := token.Claims.(jwtgo.MapClaims)

	iss, ok := claims[IssuerFieldName]
	if !ok {
		return token, fmt.Errorf("token does not contain issuer")
	}
	issStr := iss.(string)
	if strings.Contains(issStr, "cognito-idp") {
		err = validateAWSJwtClaims(claims, mw.Region, mw.UserPoolID, mw.AllowedClientIds)
		if err != nil {
			return token, err
		}
	}

	if token.Valid {
		return token, nil
	}
	return token, err
}

// validateAWSJwtClaims validates AWS Cognito User Pool JWT
func validateAWSJwtClaims(claims jwtgo.MapClaims, region, userPoolID string, allowedClientIds []string) error {
	var err error
	// 3. Check the iss claim. It should match your user pool.
	issShouldBe := fmt.Sprintf("https://cognito-idp.%v.amazonaws.com/%v", region, userPoolID)
	err = validateClaimItem(IssuerFieldName, []string{issShouldBe}, claims)
	if err != nil {
		logrus.Errorf("Failed to validate the jwt token claims %v", err)
		return err
	}

	// 4. Check the token_use claim.
	validateTokenUse := func() error {
		if tokenUse, ok := claims["token_use"]; ok {
			if tokenUseStr, ok := tokenUse.(string); ok {
				if tokenUseStr == "id" || tokenUseStr == "access" {
					return nil
				}
			}
		}
		return errors.New("token_use should be id or access")
	}

	err = validateTokenUse()
	if err != nil {
		return err
	}

	// 7. Check the exp claim and make sure the token is not expired.
	err = validateExpired(claims)
	if err != nil {
		return err
	}

	// 8. Check client id must be in the allowed list
	err = validateClientId(claims, allowedClientIds)
	if err != nil {
		return err
	}

	return nil
}

func validateClaimItem(key string, keyShouldBe []string, claims jwtgo.MapClaims) error {
	if val, ok := claims[key]; ok {
		if valStr, ok := val.(string); ok {
			for _, shouldBe := range keyShouldBe {
				if valStr == shouldBe {
					return nil
				}
			}
		}
	}
	return fmt.Errorf("%v does not match any of valid values: %v", key, keyShouldBe)
}

func validateExpired(claims jwtgo.MapClaims) error {
	if tokenExp, ok := claims["exp"]; ok {
		if exp, ok := tokenExp.(float64); ok {
			now := time.Now().Unix()
			if int64(exp) > now {
				return nil
			}
		}
		return errors.New("cannot parse token exp")
	}
	return errors.New("token is expired")
}

func validateClientId(claims jwtgo.MapClaims, allowedClientIds []string) error {
	if tokenClientId, ok := claims["client_id"]; ok {
		if clientId, ok := tokenClientId.(string); ok {
			for _, v := range allowedClientIds {
				if v == clientId {
					return nil
				}
			}
			return fmt.Errorf("this clientid %v is not allowed", clientId)
		}
		return errors.New("cannot parse token clientID")
	}
	return errors.New("token clientID part is not found")
}

func convertKey(rawE, rawN string) *rsa.PublicKey {
	decodedE, err := base64.RawURLEncoding.DecodeString(rawE)
	if err != nil {
		panic(err)
	}
	if len(decodedE) < 4 {
		nData := make([]byte, 4)
		copy(nData[4-len(decodedE):], decodedE)
		decodedE = nData
	}
	pubKey := &rsa.PublicKey{
		N: &big.Int{},
		E: int(binary.BigEndian.Uint32(decodedE[:])),
	}
	decodedN, err := base64.RawURLEncoding.DecodeString(rawN)
	if err != nil {
		panic(err)
	}
	pubKey.N.SetBytes(decodedN)
	return pubKey
}

// Download the json web public key for the given user pool id
func getJWK(jwkURL string) (map[string]JWKKey, error) {
	logrus.Infof("Downloading the jwk from the given url %s", jwkURL)
	jwk := &JWK{}

	var myClient = &http.Client{Timeout: 10 * time.Second}
	r, err := myClient.Get(jwkURL)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(r.Body)
	if err := json.NewDecoder(r.Body).Decode(jwk); err != nil {
		return nil, err
	}

	jwkMap := make(map[string]JWKKey)
	for _, jwk := range jwk.Keys {
		jwkMap[jwk.Kid] = jwk
	}
	return jwkMap, nil
}
