package oidc

import (
	"errors"
)

type Provider interface {
	CreateAuthzSession(AuthRequest) (*AuthzSession, error)
}

type ProviderConfig struct {
	ClientService ClientService
}

// FlowAction is an action during the procession of an authorization request.
type FlowAction func(*AuthzSession) error

// FlowProcessor wraps a FlowAction to make it chainable.
type FlowProcessor func(FlowAction) FlowAction

func NewProvider(config ProviderConfig) Provider {
	p := provider{
		clients: config.ClientService,
		fhdict:  make(map[FlowSpec]FlowAction),
	}
	err := p.registerFlowHandler(CODE, makeFlowHandler(CODE))
	if err != nil {
		panic("wrong config")
	}
	return p
}

type provider struct {
	clients ClientService
	fhdict  map[FlowSpec]FlowAction
}

// LoadFlowHandler returns FlowHandler for FlowSpec or error "unsupported".
func (p provider) registerFlowHandler(fs FlowSpec, fa FlowAction) error {
	if _, ok := p.fhdict[fs]; ok {
		return errors.New("flow handler already registered")
	}
	p.fhdict[fs] = fa
	return nil
}

func (p provider) FlowAction(fs FlowSpec) (FlowAction, error) {
	if fa, ok := p.fhdict[fs]; ok {
		return fa, nil
	}
	return nil, errors.New("unsupported flow type")
}

func (p provider) CreateAuthzSession(ar AuthRequest) (*AuthzSession, error) {
	fs, err := parseFlowSpec(ar)
	if err != nil {
		return nil, err
	}
	c, err := p.clients.Load(ar.ClientID)
	if err != nil {
		return nil, err
	}
	as := AuthzSession{Flow: fs, Phase: STARTING, AuthReq: ar, Client: c}
	fa, err := p.FlowAction(fs)
	if err != nil {
		return nil, err
	}
	err = fa(&as)
	if err != nil {
		return nil, err
	}
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
