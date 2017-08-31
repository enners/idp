package provider

import (
	"errors"
	"fmt"

	"github.com/ennersk/idp/oidc"
)

// FlowAction is an action during the procession of an authorization request.
type FlowAction func(*oidc.AuthzSession) error

// FlowProcessor wraps a FlowAction to make it chainable.
type FlowProcessor func(FlowAction) FlowAction

func New(config Config) oidc.Provider {
	p := provider{
		actions: make(map[oidc.FlowPhase]FlowAction),
		clients: config.ClientService,
	}

	/*
		err := p.registerFlowHandler(oidc.CODE, makeFlowHandler(oidc.CODE))
		if err != nil {
			panic("wrong config")
		}
	*/
	p.actions[oidc.FP_AUTHZ_START] = newAuthzStarter([]string{"code"}, []string{" "}, false)
	p.actions[oidc.FP_AUTHZ_CLIENT] = newClientApprover()
	return p
}

type provider struct {
	actions map[oidc.FlowPhase]FlowAction
	clients oidc.ClientService
}

// LoadFlowHandler returns FlowHandler for FlowSpec or error "unsupported".
/*func (p provider) registerFlowHandler(fs oidc.FlowSpec, fa FlowAction) error {
	if _, ok := p.fhdict[fs]; ok {
		return errors.New("flow handler already registered")
	}
	p.fhdict[fs] = fa
	return nil
}*/

func (p provider) FlowAction(fs oidc.FlowPhase) (FlowAction, error) {
	if fa, ok := p.actions[fs]; ok {
		return fa, nil
	}
	return nil, errors.New("unsupported flow type")
}

func (p provider) NewAuthzSession(ar oidc.AuthRequest) (*oidc.AuthzSession, error) {
	as := oidc.AuthzSession{AuthReq: ar}
	fa, err := p.FlowAction(oidc.FP_AUTHZ_START)
	if err != nil {
		panic("WRONG CONFIG")
	}
	err = fa(&as)
	if err != nil {
		return &as, err
	}
	fmt.Println("RT is supported")
	c, err := p.clients.Load(ar.ClientID)
	if err != nil { // client err: unknown client
		return nil, err
	}
	as.Client = c
	fa, err = p.FlowAction(oidc.FP_AUTHZ_CLIENT)
	if err != nil { // srv err : not supported flow
		return nil, err
	}
	err = fa(&as)
	if err != nil {
		return nil, err
	}
	fmt.Println("client authorized for request")
	return &as, nil
}
