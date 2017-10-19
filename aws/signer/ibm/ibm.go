// Package ibm implements signing for IBM IAM
package ibm

import (
	"net/http"

	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/request"
)

// Signer applies IBM IAM signing to given request.
type Signer struct {
	// The authentication credentials the request will be signed against.
	// This value must be set to sign requests.
	Credentials *credentials.Credentials
}

// NewSigner returns a Signer pointer configured with the credentials and optional
// option values provided. If not options are provided the Signer will use its
// default configuration.
func NewSigner(credentials *credentials.Credentials) *Signer {
	ibm := &Signer{
		Credentials: credentials,
	}

	return ibm
}

// Sign signs IBM IAM requests.
func (ibm Signer) Sign(r *http.Request, op *request.Operation) error {
	creds, err := ibm.Credentials.Get()
	if err != nil {
		return err
	}

	r.Header.Add("Authorization", "Bearer "+creds.SessionToken)
	if op.Name == "ListBuckets" || op.Name == "CreateBucket" {
		r.Header.Add("ibm-service-instance-id", creds.ServiceInstanceID)
	}
	return nil
}

// SignRequestHandler is a named request handler the SDK will use to sign
// service client request with using the V4 signature.
var SignRequestHandler = request.NamedHandler{
	Name: "ibm.SignRequestHandler", Fn: SignRequest,
}

// SignRequest signs IBM IAM requests.
func SignRequest(req *request.Request) {
	ibm := NewSigner(req.Config.Credentials)

	err := ibm.Sign(req.HTTPRequest, req.Operation)
	if err != nil {
		req.Error = err
		return
	}
}
