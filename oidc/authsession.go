package oidc

import ()

type FlowSpec int

const (
	INVALID FlowSpec = iota
	CODE
	IMPLICIT
	PASSWORD
	CLIENT_CREDENTIALS
	REFRESH
	EXTENSION
	HYBRID
)

const (
	STARTING = iota
	GRANTING
	AUTHORIZED
)

type AuthzService interface {
}

type AuthzServiceConfig struct {
}

func NewAuthzService(config AuthzServiceConfig) (AuthzSession, error) {
	return AuthzSession{}, nil
}

type AuthzSession struct {
	Flow    FlowSpec
	Phase   int
	AuthReq AuthRequest
}

type ass struct {
}
