package provider

import (
	"github.com/ennersk/idp/oidc"
)

type Config struct {
	ClientService oidc.ClientService
}
