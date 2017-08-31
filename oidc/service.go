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

type FlowPhase int

const (
	FP_AUTHZ_START FlowPhase = iota
	FP_AUTHZ_CLIENT
	FP_AQUIRING_SUBJECT
	CLIENT_APPROVED
	GRANTING
	AUTHORIZED
)

type Provider interface {
	NewAuthzSession(AuthRequest) (*AuthzSession, error)
}
