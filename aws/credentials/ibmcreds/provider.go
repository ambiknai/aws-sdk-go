// Package ibmcreds provides support for retrieving credentials from IBM IAM
// endpoint.
package ibmcreds

import (
	"encoding/json"
	"net/http"
	"time"

	"fmt"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"net/url"
)

// ProviderName is the name of the credentials provider.
const ProviderName = "IBMIAMProvider"

// defaultIAMEndPoint is the default URL of the IBM IAM endpoint
const defaultIAMEndPoint = "https://iam.bluemix.net/oidc/token"

// Provider satisfies the credentials.Provider interface, and is a client to
// retrieve credentials from IBM IAM endpoint.
type Provider struct {
	credentials.Expiry

	apiKey            string
	serviceInstanceID string

	// IAMEndpoint
	IAMEndpoint string

	// ExpiryWindow will allow the credentials to trigger refreshing prior to
	// the credentials actually expiring. This is beneficial so race conditions
	// with expiring credentials do not cause request to fail unexpectedly
	// due to ExpiredTokenException exceptions.
	//
	// So a ExpiryWindow of 10s would cause calls to IsExpired() to return true
	// 10 seconds before the credentials are actually expired.
	//
	// If ExpiryWindow is 0 or less it will be ignored.
	ExpiryWindow time.Duration
}

// NewProviderClient returns a credentials Provider for retrieving IBM IAM
// credentials from IBM IAM endpoint.
func NewProviderClient(apiKey, serviceInstanceID, iamEndpoint string) credentials.Provider {
	p := &Provider{
		serviceInstanceID: serviceInstanceID,
		apiKey:            apiKey,
		IAMEndpoint:       iamEndpoint,
	}

	return p
}

// NewCredentialsClient returns a Credentials wrapper for retrieving credentials
// from IBM IAM endpoint.
func NewCredentialsClient(apiKey, serviceInstanceID, iamEndpoint string) *credentials.Credentials {
	return credentials.NewTypedCredentials(NewProviderClient(apiKey, serviceInstanceID, iamEndpoint), "ibm-iam")
}

// IsExpired returns true if the credentials retrieved are expired, or not yet
// retrieved.
func (p *Provider) IsExpired() bool {
	return p.Expiry.IsExpired()
}

// Retrieve will attempt to request the credentials from the endpoint the Provider
// was configured for. And error will be returned if the retrieval fails.
func (p *Provider) Retrieve() (credentials.Value, error) {
	resp, err := p.getCredentials()
	if err != nil {
		return credentials.Value{ProviderName: ProviderName},
			awserr.New("CredentialsEndpointError", "failed to load credentials", err)
	}

	p.SetExpiration(time.Unix(resp.Expiration, 0), p.ExpiryWindow)

	return credentials.Value{
		ServiceInstanceID: p.serviceInstanceID,
		SessionToken:      resp.AccessToken,
		ProviderName:      ProviderName,
	}, nil
}

type getCredentialsOutput struct {
	Expiration  int64  `json:"expiration"`
	AccessToken string `json:"access_token"`
}

func (p *Provider) getCredentials() (*getCredentialsOutput, error) {
	var IAMEndpointURL string
	if p.IAMEndpoint != "" {
		IAMEndpointURL = p.IAMEndpoint + "/oidc/token"
	} else {
		IAMEndpointURL = defaultIAMEndPoint
	}
	resp, err := http.PostForm(IAMEndpointURL,
		url.Values{
			"grant_type":    {"urn:ibm:params:oauth:grant-type:apikey"},
			"response_type": {"cloud_iam"},
			"apikey":        {p.apiKey}})

	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("server returned status %d instead of 200", resp.StatusCode)
	}

	out := &getCredentialsOutput{}
	err = json.NewDecoder(resp.Body).Decode(out)

	if err != nil {
		return nil, err
	}

	return out, nil
}
