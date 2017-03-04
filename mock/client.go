package mock

import (
	"fmt"
	"github.com/ennersk/idp/oidc"
)

type ClientSvc struct{}

func (cs ClientSvc) Load(ID string) (oidc.Client, error) {
	fmt.Println("bin im mock, cid: %v", ID)
	return oidc.Client{
		Name:         "mockClient",
		ID:           ID,
		Secret:       "secret",
		RedirectURLs: []string{"https://example.com/callback"},
	}, nil
}
