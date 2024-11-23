package jwt

import (
	"github.com/Digital-Insight-Technologies-Ltd/gin-jwt-cognito/models"
	"github.com/sirupsen/logrus"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/go-errors/errors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// UserClaimsKey is the key for user claims in our context
const UserClaimsKey = "userClaims"

// CognitoClaimsMiddleware is a middleware for Gin that extracts user claims from
// AWS Cognito.
func CognitoClaimsMiddleware() gin.HandlerFunc {
	// parser
	jwtParser := new(jwt.Parser)

	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Missing or invalid Authorization header"})
			return
		}
		claims, err := parseClaims(jwtParser, authHeader[7:])

		if err != nil {
			logrus.WithError(err).Error("Error parsing claims (OIDC: stage 1)")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid user claims (OIDC: stage 1)"})
			return
		}

		userCtx, err := constructUserContext(claims)

		if err != nil {
			logrus.WithError(err).Error("Error constructing user context (OIDC: stage 2)")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid user claims (OIDC: stage 2)"})
			return
		}

		// Add the claims to Gin's context
		c.Set(UserClaimsKey, userCtx)

		// Proceed with the middleware chain
		c.Next()
	}
}

func parseClaims(jwtParser *jwt.Parser, claimsHeader string) (jwt.MapClaims, error) {
	tok, _, err := jwtParser.ParseUnverified(claimsHeader, jwt.MapClaims{})
	if err != nil {
		logrus.WithError(err).Error("Error parsing claims")
		return nil, err
	}

	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid claims type")
	}

	return claims, nil
}

func parseUUID(claims jwt.MapClaims, key string) (uuid.UUID, error) {
	idString, ok := claims[key].(string)
	if !ok {
		return uuid.UUID{}, errors.New("Invalid " + key + " format")
	}
	id, err := uuid.Parse(idString)
	if err != nil {
		logrus.WithError(err).Errorf("Error parsing claims, Invalid user claims (failed to parse %v UUID)", key)
		return uuid.UUID{}, errors.New("Invalid user claims (failed to parse " + key + " UUID)")
	}
	return id, nil
}

func constructUserContext(claims jwt.MapClaims) (models.UserContext, error) {
	email, ok := claims["email"].(string)
	if !ok {
		return models.UserContext{}, errors.New("Invalid email format")
	}

	userID, err := parseUUID(claims, "sub")
	if err != nil {
		return models.UserContext{}, err
	}

	tenantID, err := parseUUID(claims, "custom:tenantId")
	if err != nil {
		return models.UserContext{}, err
	}

	organisationID, err := parseUUID(claims, "custom:organisationId")
	if err != nil {
		return models.UserContext{}, err
	}

	// Decode the claims
	return models.UserContext{
		UserID:         userID,
		TenantID:       tenantID,
		OrganisationID: organisationID,
		Email:          email,
	}, nil
}
