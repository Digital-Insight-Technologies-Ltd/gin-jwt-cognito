package jwt

import (
	"github.com/Digital-Insight-Technologies-Ltd/gin-jwt-cognito/models"
	"net/http"

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
	return func(c *gin.Context) {
		claims, err := parseClaims(c.GetHeader("Authorization")[7:])
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid user claims (OIDC: stage 1)"})
			return
		}

		userCtx, err := constructUserContext(claims)

		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid user claims (OIDC: stage 2)"})
			return
		}

		// Add the claims to Gin's context
		c.Set(UserClaimsKey, userCtx)

		// Proceed with the middleware chain
		c.Next()
	}
}

func parseClaims(claimsHeader string) (jwt.MapClaims, error) {
	tok, _, err := new(jwt.Parser).ParseUnverified(claimsHeader, jwt.MapClaims{})
	if err != nil {
		return nil, err
	}

	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		return nil, err
	}

	return claims, nil
}

func constructUserContext(claims jwt.MapClaims) (models.UserContext, error) {
	email, ok := claims["email"].(string)
	if !ok {
		return models.UserContext{}, errors.New("Invalid email format")
	}
	userIDString, ok := claims["sub"].(string)
	if !ok {
		return models.UserContext{}, errors.New("Invalid UserID format")
	}
	userID, err := uuid.Parse(userIDString)
	if err != nil {
		return models.UserContext{}, errors.New("Invalid user claims (failed to parse UserID UUID)")
	}
	tenantIDString, ok := claims["custom:tenantId"].(string)
	if !ok {
		return models.UserContext{}, errors.New("Invalid TenantID format")
	}
	tenantID, err := uuid.Parse(tenantIDString)
	if err != nil {
		return models.UserContext{}, errors.New("Invalid user claims (failed to parse TenantID UUID)")
	}
	organisationIDString, ok := claims["custom:organisationId"].(string)
	if !ok {
		return models.UserContext{}, errors.New("Invalid OrganisationID format")
	}
	organisationID, err := uuid.Parse(organisationIDString)
	if err != nil {
		return models.UserContext{}, errors.New("Invalid user claims (failed to parse OrganisationID UUID)")
	}

	// Decode the claims
	return models.UserContext{
		UserID:         userID,
		TenantID:       tenantID,
		OrganisationID: organisationID,
		Email:          email,
	}, nil
}
