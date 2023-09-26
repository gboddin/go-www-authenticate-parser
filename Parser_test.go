package www_authenticate_parser

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

var Test1 = "Bearer test , realm=955958a3-ac21-430d-ac83-6d58226f5f80,client_id=\"00000003\\\"-0000-0ff1-ce00-000000000000\", trusted_issuers=\"00000003-0000-0ff1-ce00-000000000000@955958a3-ac21-430d-ac83-6d58226f5f80\""
var Test2 = "Digest\n    realm=\"http-auth@example.org\",\n    qop=\"auth, auth-int\",\n    algorithm=MD5,\n    nonce=\"7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v\",\n    opaque=\"FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS\""

func TestParseDigest(t *testing.T) {
	digest := Parse(Test1)
	assert.Equal(t, digest.AuthType, "Bearer")
	testParam, found := digest.Params["test"]
	assert.True(t, found)
	assert.Equal(t, "true", testParam)
	realm, found := digest.Params["realm"]
	assert.True(t, found)
	assert.Equal(t, "955958a3-ac21-430d-ac83-6d58226f5f80", realm)
	clientId, found := digest.Params["client_id"]
	assert.True(t, found)
	assert.Equal(t, "00000003\"-0000-0ff1-ce00-000000000000", clientId)

	digest = Parse(Test2)
	assert.Equal(t, digest.AuthType, "Digest")
	realm, found = digest.Params["realm"]
	assert.True(t, found)
	assert.Equal(t, "http-auth@example.org", realm)
	algo, found := digest.Params["algorithm"]
	assert.True(t, found)
	assert.Equal(t, "MD5", algo)
}
