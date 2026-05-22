package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := map[string]struct {
		headers    http.Header
		wantAPIKey string
		wantErr    error
	}{
		"missing authorization header": {
			headers:    http.Header{},
			wantAPIKey: "",
			wantErr:    ErrNoAuthHeaderIncluded,
		},
		"malformed authorization header": {
			headers: http.Header{
				"Authorization": []string{"Bearer abc123"},
			},
			wantAPIKey: "",
			wantErr:    errors.New("malformed authorization header"),
		},
		"valid api key": {
			headers: http.Header{
				"Authorization": []string{"ApiKey abc123"},
			},
			wantAPIKey: "abc123",
			wantErr:    nil,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			gotAPIKey, gotErr := GetAPIKey(tc.headers)

			if gotAPIKey != tc.wantAPIKey {
				t.Fatalf("expected api key %q, got %q", tc.wantAPIKey, gotAPIKey)
			}

			if tc.wantErr == nil && gotErr != nil {
				t.Fatalf("expected no error, got %v", gotErr)
			}

			if tc.wantErr != nil && gotErr == nil {
				t.Fatalf("expected error %v, got nil", tc.wantErr)
			}

			if tc.wantErr != nil && gotErr.Error() != tc.wantErr.Error() {
				t.Fatalf("expected error %v, got %v", tc.wantErr, gotErr)
			}
		})
	}
}