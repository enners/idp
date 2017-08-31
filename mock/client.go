package mock

import (
	"errors"
	"fmt"
	"github.com/ennersk/idp/oidc"
)

type ClientSvc struct{}

func (cs ClientSvc) Load(ID string) (oidc.Client, error) {
	fmt.Println("bin im mock, cid: %v", ID)
	if ID == "NON-EXISTANT" {
		return *new(oidc.Client), errors.New("client does not exist")
	}
	return oidc.Client{
		Name:          "mockClient_" + ID,
		ID:            ID,
		Secret:        "secret",
		RedirectURLs:  []string{"https://example.com/callback"},
		ResponseTypes: []string{"code"},
	}, nil
}
