package s3api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/seaweedfs/seaweedfs/weed/iam/integration"
	"github.com/seaweedfs/seaweedfs/weed/iam/policy"
	"github.com/seaweedfs/seaweedfs/weed/iam/sts"
	"github.com/seaweedfs/seaweedfs/weed/s3api/s3_constants"
	"github.com/seaweedfs/seaweedfs/weed/s3api/s3err"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Conditions on a request's x-amz-* headers (s3:x-amz-object-lock-mode,
// s3:x-amz-server-side-encryption, ...) must hold for the credentials of an
// STS session as they do for static identities. A Deny that is never matched
// because the header never reached the condition context silently fails open.
func TestSTSSessionPolicyEvaluatesAmzHeaderConditions(t *testing.T) {
	ctx := context.Background()
	iamManager := setupGroupsRolesIAMManager(t)
	s3iam := NewS3IAMIntegration(iamManager, "localhost:8888")

	require.NoError(t, iamManager.CreatePolicy(ctx, "", "HeaderConditionPolicy", &policy.PolicyDocument{
		Version: "2012-10-17",
		Statement: []policy.Statement{
			{
				Sid:      "AllowWrites",
				Effect:   "Allow",
				Action:   []string{"s3:PutObject"},
				Resource: []string{"arn:aws:s3:::locked-bucket/*", "arn:aws:s3:::kms-bucket/*"},
			},
			{
				Sid:      "DenyObjectLock",
				Effect:   "Deny",
				Action:   []string{"s3:PutObject"},
				Resource: []string{"arn:aws:s3:::locked-bucket/*"},
				Condition: map[string]map[string]interface{}{
					"StringEquals": {"s3:x-amz-object-lock-mode": []string{"GOVERNANCE", "COMPLIANCE"}},
				},
			},
			{
				Sid:      "DenyUnencrypted",
				Effect:   "Deny",
				Action:   []string{"s3:PutObject"},
				Resource: []string{"arn:aws:s3:::kms-bucket/*"},
				Condition: map[string]map[string]interface{}{
					"StringNotEquals": {"s3:x-amz-server-side-encryption": "aws:kms"},
				},
			},
		},
	}))
	require.NoError(t, iamManager.CreateRole(ctx, "", "HeaderConditionRole", &integration.RoleDefinition{
		RoleName: "HeaderConditionRole",
		TrustPolicy: &policy.PolicyDocument{
			Version: "2012-10-17",
			Statement: []policy.Statement{{
				Effect:    "Allow",
				Principal: map[string]interface{}{"Federated": "test-oidc"},
				Action:    []string{"sts:AssumeRoleWithWebIdentity"},
			}},
		},
		AttachedPolicies: []string{"HeaderConditionPolicy"},
	}))
	response, err := iamManager.AssumeRoleWithWebIdentity(ctx, &sts.AssumeRoleWithWebIdentityRequest{
		RoleArn:          "arn:aws:iam::role/HeaderConditionRole",
		WebIdentityToken: groupsRolesJWT(t, "header-user", nil, nil),
		RoleSessionName:  "header-session",
	})
	require.NoError(t, err)
	identity, errCode := authenticateSessionToken(t, s3iam, response.Credentials.SessionToken)
	require.Equal(t, s3err.ErrNone, errCode)

	put := func(bucket string, headers map[string]string) s3err.ErrorCode {
		req := httptest.NewRequest("PUT", "/"+bucket+"/file.txt", http.NoBody)
		req.Header.Set("Authorization", "Bearer "+identity.SessionToken)
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		return s3iam.AuthorizeAction(ctx, identity, s3_constants.ACTION_WRITE, bucket, "file.txt", req)
	}

	// s3:x-amz-object-lock-mode: a positive Deny that must fire.
	assert.Equal(t, s3err.ErrNone, put("locked-bucket", nil), "a write without a lock is allowed")
	assert.Equal(t, s3err.ErrAccessDenied, put("locked-bucket", map[string]string{"X-Amz-Object-Lock-Mode": "GOVERNANCE"}),
		"a Deny on s3:x-amz-object-lock-mode must hold for a session")

	// s3:x-amz-server-side-encryption: a negated Deny must not fire for a
	// matching header, and must fire for any other value or none.
	assert.Equal(t, s3err.ErrNone, put("kms-bucket", map[string]string{"X-Amz-Server-Side-Encryption": "aws:kms"}),
		"a kms-encrypted write is allowed")
	assert.Equal(t, s3err.ErrAccessDenied, put("kms-bucket", map[string]string{"X-Amz-Server-Side-Encryption": "AES256"}),
		"a write with another encryption is denied")
	assert.Equal(t, s3err.ErrAccessDenied, put("kms-bucket", nil), "a write with no encryption header is denied")
}
