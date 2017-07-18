package oidc

import (
	"context"

	"github.com/go-kit/kit/endpoint"
)

type Endpoints struct {
	AuthorizeEndpoint endpoint.Endpoint
}

func MakeAuthorizeEndpoint(idp Provider) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		v, err := idp.CreateAuthzSession(request.(AuthRequest))
		return v, err
	}
}
