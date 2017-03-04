package oidc

import (
	"fmt"
)

type Provider interface {
	InitAuthReq(AuthRequest) (LoginHint, error)
}

type ProviderConfig struct {
	ClientService ClientService
}

type defaultProvider struct {
	ClientService ClientService
}

func (p defaultProvider) InitAuthReq(ar AuthRequest) (LoginHint, error) {
	client, err := p.ClientService.Load(ar.ClientID)
	// TODO handle ErrClientInvalid
	fmt.Printf("client: %v, error: %v\n", client, err)
	// TODO register auth req
	return LoginHint{AMR: "pwd", State: ar.State}, nil
}

func NewProvider(config ProviderConfig) Provider {
	return defaultProvider{
		ClientService: config.ClientService,
	}
}
