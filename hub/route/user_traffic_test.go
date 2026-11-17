package route

import (
	"encoding/json"
	"testing"

	"github.com/metacubex/http/httptest"
)

func TestUserTrafficRequiresControllerAuthentication(t *testing.T) {
	h := router(false, "test-controller-secret", "", Cors{})
	request := httptest.NewRequest("GET", "/user-traffic", nil)
	response := httptest.NewRecorder()
	h.ServeHTTP(response, request)
	if response.Code != 401 {
		t.Fatalf("unauthenticated status: %d", response.Code)
	}
	request.Header.Set("Authorization", "Bearer test-controller-secret")
	response = httptest.NewRecorder()
	h.ServeHTTP(response, request)
	var body struct {
		Epoch string         `json:"epoch"`
		Users map[string]any `json:"users"`
	}
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &body) != nil || body.Epoch == "" || body.Users == nil {
		t.Fatalf("invalid response: %d %s", response.Code, response.Body.String())
	}
}
