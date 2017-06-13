package oidc

import (
	"errors"
	"fmt"
)

type Provider interface {
	InitAuthReq(AuthRequest) (LoginHint, error)
}

type ProviderConfig struct {
	ClientService ClientService
}

type FlowHandler interface {
	FlowSpec() FlowSpec
	InitFunc() func(*AuthzSession) (*AuthzSession, error)
}

func NewProvider(config ProviderConfig) Provider {
	return provider{
		clients: config.ClientService,
	}
}

type provider struct {
	clients ClientService
}

func (p provider) InitAuthReq(ar AuthRequest) (LoginHint, error) {
	client, err := p.clients.Load(ar.ClientID)
	if err != nil {
		return LoginHint{}, &Error{ERR_SERVER, errors.New("client service failure"), err.Error()}
	}

	// TODO handle ErrClientInvalid
	fmt.Printf("client: %v, error: %v\n", client, err)
	// TODO is client registered for flow and response type?
	// from here on valid; e.g. excessive scopes will be ignored

	// TODO register auth req
	return LoginHint{AMR: "pwd", State: ar.State}, nil
}

func (p provider) StartAuthzSession(ar AuthRequest) (*AuthzSession, error) {
	flow, err := parseFlowSpec(ar)
	if err != nil {
		return nil, err
	}

	as := AuthzSession{Flow: flow, Phase: STARTING}
	return &as, nil
}

func parseFlowSpec(ar AuthRequest) (FlowSpec, error) {
	switch ar.ResponseType {
	case "code":
		return CODE, nil
	case "token":
		return IMPLICIT, nil
	default:
		return INVALID, errors.New(ERR_RESPONSE_TYPE)
	}
}

/*
func validateClient(c *Client, ar *AuthRequest) (Client, error) {
	if c == nil {
		return
	}
}

func (p provider) loadValidClientFor(ar *AuthRequest) (Client, error) {
	c, err := p.clients.Load(ar.ClientID)
	if err != nil {
		return nil, errors.New("unknown client")
	}

}
*/
