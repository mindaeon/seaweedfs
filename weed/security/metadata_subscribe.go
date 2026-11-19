package security

import (
	"context"
	"path"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/seaweedfs/seaweedfs/weed/glog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// The filer gRPC methods a scoped metadata token may name in allowed_methods.
const (
	MethodSubscribeMetadata      = "SubscribeMetadata"
	MethodSubscribeLocalMetadata = "SubscribeLocalMetadata"
)

// GenJwtForMetadataSubscription mints a read-only token for the filer's
// SubscribeMetadata and SubscribeLocalMetadata calls, limited to events under
// the given path prefixes. It is signed with jwt.filer_signing.subscribe.key
// and carries the same allowed_prefixes and allowed_methods claims as a scoped
// filer token, so it is never an admin token (see IsFilerAdminToken).
// It returns an empty string without a key or without a usable prefix.
func GenJwtForMetadataSubscription(signingKey SigningKey, expiresAfterSec int, prefixes []string) EncodedJwt {
	prefixes = CleanMetadataPrefixes(prefixes)
	if len(signingKey) == 0 || len(prefixes) == 0 {
		return ""
	}
	claims := SeaweedFilerClaims{
		AllowedPrefixes: prefixes,
		AllowedMethods:  []string{MethodSubscribeMetadata, MethodSubscribeLocalMetadata},
	}
	if expiresAfterSec > 0 {
		claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(time.Second * time.Duration(expiresAfterSec)))
	}
	encoded, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(signingKey))
	if err != nil {
		glog.V(0).Infof("Failed to sign metadata subscription claims: %v", err)
		return ""
	}
	return EncodedJwt(encoded)
}

// CleanMetadataPrefixes returns the absolute, cleaned prefixes of the input,
// dropping empty and relative ones.
func CleanMetadataPrefixes(prefixes []string) []string {
	var cleaned []string
	for _, p := range prefixes {
		if !strings.HasPrefix(p, "/") {
			continue
		}
		cleaned = append(cleaned, path.Clean(p))
	}
	return cleaned
}

// MetadataPathInScope reports whether fullPath is one of the prefixes or below
// one of them, by whole path segments: "/buckets/a" holds "/buckets/a/x" and
// not "/buckets/ab".
func MetadataPathInScope(fullPath string, prefixes []string) bool {
	fullPath = path.Clean("/" + fullPath)
	for _, p := range prefixes {
		if p == "/" || fullPath == p || strings.HasPrefix(fullPath, p+"/") {
			return true
		}
	}
	return false
}

// metadataSubscriptionScope returns the prefixes of a valid scoped token for
// method signed by signingKey. A token with a session id, without prefixes, or
// naming any method other than the two subscribe calls is refused.
func metadataSubscriptionScope(signingKey SigningKey, token EncodedJwt, method string) ([]string, bool) {
	if len(signingKey) == 0 || token == "" {
		return nil, false
	}
	parsed, err := DecodeJwt(signingKey, token, &SeaweedFilerClaims{})
	if err != nil || parsed == nil || !parsed.Valid {
		return nil, false
	}
	claims, ok := parsed.Claims.(*SeaweedFilerClaims)
	if !ok || claims.SessionId != "" || len(claims.AllowedPrefixes) == 0 || len(claims.AllowedMethods) == 0 {
		return nil, false
	}
	allowsMethod := false
	for _, m := range claims.AllowedMethods {
		switch m {
		case MethodSubscribeMetadata, MethodSubscribeLocalMetadata:
		default:
			return nil, false
		}
		if m == method {
			allowsMethod = true
		}
	}
	if !allowsMethod {
		return nil, false
	}
	prefixes := CleanMetadataPrefixes(claims.AllowedPrefixes)
	if len(prefixes) != len(claims.AllowedPrefixes) {
		return nil, false
	}
	return prefixes, true
}

// CheckGrpcMetadataSubscription authorizes a metadata subscription call.
//
// With no subscribeKey configured the call is unrestricted, as before: the
// returned scope is nil. With one, the caller must be an mTLS-verified peer or
// present an admin token (signed by adminKey), both unrestricted, or a scoped
// token signed by subscribeKey, in which case the returned prefixes are the
// only paths its events may name.
func CheckGrpcMetadataSubscription(ctx context.Context, subscribeKey, adminKey SigningKey, method string) (scope []string, err error) {
	if len(subscribeKey) == 0 || isMtlsVerifiedPeer(ctx) {
		return nil, nil
	}
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "missing metadata")
	}
	authHeaders := md.Get("authorization")
	if len(authHeaders) > maxGrpcAdminAuthValues {
		authHeaders = authHeaders[:maxGrpcAdminAuthValues]
	}
	for _, raw := range authHeaders {
		parts := strings.Fields(raw)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" {
			continue
		}
		token := EncodedJwt(parts[1])
		if IsFilerAdminToken(adminKey, token) {
			return nil, nil
		}
		if prefixes, ok := metadataSubscriptionScope(subscribeKey, token, method); ok {
			return prefixes, nil
		}
	}
	return nil, status.Error(codes.Unauthenticated, "metadata subscription requires a valid admin token or a scoped subscription token")
}
