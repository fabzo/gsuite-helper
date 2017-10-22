package gsuite_helper

import (
	"golang.org/x/oauth2/jwt"
	"encoding/json"
	"log"
	"google.golang.org/api/admin/directory/v1"
	"context"
	"net/http"
	"github.com/fabzo/gsuite-helper/directory"
)

type Client struct {
	Directory *directory.Service
}

func New(credentials []byte, subject string, customerId string, domain string) (*Client, error) {
	var credentialsMap map[string]string
	err := json.Unmarshal(credentials, &credentialsMap)
	if err != nil {
		return nil, err
	}

	config := &jwt.Config{
		Email:        string(credentialsMap["client_email"]),
		PrivateKey:   []byte(credentialsMap["private_key"]),
		PrivateKeyID: string(credentialsMap["private_key_id"]),
		Scopes:       []string{admin.AdminDirectoryGroupReadonlyScope, admin.AdminDirectoryGroupMemberReadonlyScope},
		TokenURL:     string(credentialsMap["token_uri"]),
		Subject:      subject,
	}

	httpClient := config.Client(context.Background())

	return NewWithHttpClient(httpClient, customerId, domain)
}

func NewWithHttpClient(httpClient *http.Client, customerId string, domain string) (*Client, error) {
	directoryService, err := directory.New(httpClient, customerId, domain)
	if err != nil {
		return nil, err
	}

	return &Client{
		Directory:  directoryService,
	}, nil
}
