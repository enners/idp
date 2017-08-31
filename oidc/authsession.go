package oidc

import ()

type AuthzService interface {
}

type AuthzServiceConfig struct {
}

func NewAuthzService(config AuthzServiceConfig) (AuthzSession, error) {
	return AuthzSession{}, nil
}

type AuthzSession struct {
	Flow    FlowSpec
	Phase   FlowPhase
	AuthReq AuthRequest
	Client  Client
}

type ass struct {
}
