package security

import (
	"context"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func incomingBearer(token string) context.Context {
	return metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+token))
}

func TestCheckGrpcMetadataSubscription(t *testing.T) {
	subKey := SigningKey("subscribe-key")
	adminKey := SigningKey("admin-key")
	scoped := string(GenJwtForMetadataSubscription(subKey, 60, []string{"/buckets/uploads", "/buckets/logs/"}))
	if scoped == "" {
		t.Fatal("no scoped token")
	}
	sign := func(key SigningKey, claims jwt.Claims) string {
		s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(key))
		if err != nil {
			t.Fatal(err)
		}
		return s
	}

	tests := []struct {
		name      string
		ctx       context.Context
		subKey    SigningKey
		method    string
		wantScope []string
		wantCode  codes.Code
	}{
		{"feature off keeps the call open", context.Background(), nil, MethodSubscribeMetadata, nil, codes.OK},
		{"scoped token", incomingBearer(scoped), subKey, MethodSubscribeMetadata, []string{"/buckets/uploads", "/buckets/logs"}, codes.OK},
		{"scoped token, local call", incomingBearer(scoped), subKey, MethodSubscribeLocalMetadata, []string{"/buckets/uploads", "/buckets/logs"}, codes.OK},
		{"admin token is unrestricted", incomingBearer(string(GenJwtForFilerAdmin(adminKey, 60))), subKey, MethodSubscribeMetadata, nil, codes.OK},
		{"no token", context.Background(), subKey, MethodSubscribeMetadata, nil, codes.Unauthenticated},
		{"scoped token signed with another key", incomingBearer(string(GenJwtForMetadataSubscription(SigningKey("other"), 60, []string{"/a"}))), subKey, MethodSubscribeMetadata, nil, codes.Unauthenticated},
		{"scoped token signed with the admin key", incomingBearer(string(GenJwtForMetadataSubscription(adminKey, 60, []string{"/a"}))), subKey, MethodSubscribeMetadata, nil, codes.Unauthenticated},
		{"admin token signed with the subscribe key", incomingBearer(string(GenJwtForFilerAdmin(subKey, 60))), subKey, MethodSubscribeMetadata, nil, codes.Unauthenticated},
		{"token without prefixes", incomingBearer(sign(subKey, SeaweedFilerClaims{AllowedMethods: []string{MethodSubscribeMetadata}})), subKey, MethodSubscribeMetadata, nil, codes.Unauthenticated},
		{"token without methods", incomingBearer(sign(subKey, SeaweedFilerClaims{AllowedPrefixes: []string{"/a"}})), subKey, MethodSubscribeMetadata, nil, codes.Unauthenticated},
		{"token for a write method too", incomingBearer(sign(subKey, SeaweedFilerClaims{AllowedPrefixes: []string{"/a"}, AllowedMethods: []string{MethodSubscribeMetadata, "PUT"}})), subKey, MethodSubscribeMetadata, nil, codes.Unauthenticated},
		{"token for the other method only", incomingBearer(sign(subKey, SeaweedFilerClaims{AllowedPrefixes: []string{"/a"}, AllowedMethods: []string{MethodSubscribeLocalMetadata}})), subKey, MethodSubscribeMetadata, nil, codes.Unauthenticated},
		{"relative prefix", incomingBearer(sign(subKey, SeaweedFilerClaims{AllowedPrefixes: []string{"a"}, AllowedMethods: []string{MethodSubscribeMetadata}})), subKey, MethodSubscribeMetadata, nil, codes.Unauthenticated},
		{"session token", incomingBearer(sign(subKey, SeaweedFilerClaims{SessionId: "s", AllowedPrefixes: []string{"/a"}, AllowedMethods: []string{MethodSubscribeMetadata}})), subKey, MethodSubscribeMetadata, nil, codes.Unauthenticated},
		{"expired token", incomingBearer(sign(subKey, SeaweedFilerClaims{AllowedPrefixes: []string{"/a"}, AllowedMethods: []string{MethodSubscribeMetadata}, RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(jwtPast())}})), subKey, MethodSubscribeMetadata, nil, codes.Unauthenticated},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scope, err := CheckGrpcMetadataSubscription(tt.ctx, tt.subKey, adminKey, tt.method)
			if status.Code(err) != tt.wantCode {
				t.Fatalf("code = %v (%v), want %v", status.Code(err), err, tt.wantCode)
			}
			if len(scope) != len(tt.wantScope) {
				t.Fatalf("scope = %v, want %v", scope, tt.wantScope)
			}
			for i := range scope {
				if scope[i] != tt.wantScope[i] {
					t.Fatalf("scope = %v, want %v", scope, tt.wantScope)
				}
			}
		})
	}
}

// A scoped subscription token is not an admin token, for the IAM gRPC service.
func TestScopedSubscriptionTokenIsNotAdmin(t *testing.T) {
	key := SigningKey("same-key")
	token := GenJwtForMetadataSubscription(key, 60, []string{"/a"})
	if IsFilerAdminToken(key, token) {
		t.Fatal("a scoped subscription token must not count as an admin token")
	}
}

func TestMetadataPathInScope(t *testing.T) {
	prefixes := []string{"/buckets/a"}
	for path, want := range map[string]bool{
		"/buckets/a":        true,
		"/buckets/a/x/y":    true,
		"/buckets/ab":       false,
		"/buckets":          false,
		"/buckets/a/../b/x": false,
		"/buckets/a/../a/x": true,
		"/":                 false,
	} {
		if got := MetadataPathInScope(path, prefixes); got != want {
			t.Errorf("MetadataPathInScope(%q) = %v, want %v", path, got, want)
		}
	}
	if !MetadataPathInScope("/anything", []string{"/"}) {
		t.Error("the root prefix holds every path")
	}
}

func jwtPast() time.Time { return time.Now().Add(-time.Hour) }
