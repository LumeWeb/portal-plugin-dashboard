package api

import (
	"net/http"
	"testing"

	router "go.lumeweb.com/portal-router"
)

// TestOTPValidateSwagger_NoDefault200 verifies that the OTP validate endpoint
// does not include the default 200 OK response, since it returns a 302 redirect.
// This test ensures that the WithoutDefaultSuccessResponse() option is working correctly.
func TestOTPValidateSwagger_NoDefault200(t *testing.T) {
	// Build the OTP routes to get the route definitions
	api := &API{}
	routes := api.buildOTPRoutes(nil, nil, nil)
	
	// Find the OTP validate endpoint
	var validateRoute *router.Route
	for i := range routes {
		if routes[i].Path == "/api/auth/otp/validate" && routes[i].Method == http.MethodPost {
			validateRoute = &routes[i]
			break
		}
	}
	
	if validateRoute == nil {
		t.Fatal("OTP validate route not found")
	}
	
	// Verify the route has swagger definitions
	if validateRoute.Swagger.Responses == nil {
		t.Fatal("Route has no swagger responses defined")
	}
	
	// Check that 200 OK is NOT present (this is the key assertion)
	if _, has200 := validateRoute.Swagger.Responses[http.StatusOK]; has200 {
		t.Error("OTP validate endpoint should not have a 200 OK response in its swagger documentation")
	}
	
	// Check that 302 Found IS present (the expected redirect response)
	if _, has302 := validateRoute.Swagger.Responses[http.StatusFound]; !has302 {
		t.Error("OTP validate endpoint should have a 302 Found response in its swagger documentation")
	}
	
	// Verify the Location header is defined for the 302 response
	location302, ok := validateRoute.Swagger.Responses[http.StatusFound]
	if !ok {
		t.Fatal("302 response definition not found")
	}
	
	if location302.Headers == nil {
		t.Error("302 response should have headers defined")
	}
	
	if _, hasLocation := location302.Headers["Location"]; !hasLocation {
		t.Error("302 response should have a Location header")
	}
}

// TestOTPValidateSwagger_Marker verifies that the NO_DEFAULT_200 marker
// is set during route building and would be removed during registration.
func TestOTPValidateSwagger_Marker(t *testing.T) {
	// Build the OTP routes to get the route definitions
	api := &API{}
	routes := api.buildOTPRoutes(nil, nil, nil)
	
	// Find the OTP validate endpoint
	var validateRoute *router.Route
	for i := range routes {
		if routes[i].Path == "/api/auth/otp/validate" && routes[i].Method == http.MethodPost {
			validateRoute = &routes[i]
			break
		}
	}
	
	if validateRoute == nil {
		t.Fatal("OTP validate route not found")
	}
	
	// Verify NO_DEFAULT_200 marker IS present during route building
	// This marker prevents applySwaggerDefaults from adding a default 200 response.
	// The marker will be removed later by clearSwaggerMarkers during RegisterRoutes.
	if _, hasMarker := validateRoute.Swagger.Responses[-1]; !hasMarker {
		t.Error("NO_DEFAULT_200 marker should be present during route building to prevent default 200 response")
	}
	
	// Verify we have the 302 response
	if _, has302 := validateRoute.Swagger.Responses[http.StatusFound]; !has302 {
		t.Error("Should have 302 Found response")
	}
	
	// And error responses should be present
	if _, has400 := validateRoute.Swagger.Responses[http.StatusBadRequest]; !has400 {
		t.Error("Should have 400 Bad Request response")
	}
	if _, has401 := validateRoute.Swagger.Responses[http.StatusUnauthorized]; !has401 {
		t.Error("Should have 401 Unauthorized response")
	}
}
