package jwt_test

import (
	jwt "github.com/Digital-Insight-Technologies-Ltd/gin-jwt-cognito"
	"github.com/gin-gonic/gin"
)

func ExampleAuthMiddleware() {

	// Creates a gin router with default middleware:
	router := gin.Default()

	// Create Cognito JWT auth middleware and set it  in all authenticated endpoints
	mw, err := jwt.AuthJWTMiddleware("<some_iss>", "<some_userpool_id>", "region", []string{"clientid1", "clientid2"})
	if err != nil {
		panic(err)
	}

	router.GET("/someGet", mw.MiddlewareFunc(), func(context *gin.Context) {
		// some implementation
	})
	router.POST("/somePost", mw.MiddlewareFunc(), func(context *gin.Context) {
		// some implementation
	})
	router.PUT("/somePut", mw.MiddlewareFunc(), func(context *gin.Context) {
		// some implementation
	})

	// By default, it serves on :8080 unless a
	// PORT environment variable was defined.
	err = router.Run()
	if err != nil {
		return
	}
}
