package oidc

import (
	"context"
	//	"net/http"

	"github.com/go-kit/kit/endpoint"
)

type Endpoints struct {
	AuthorizeEndpoint endpoint.Endpoint
}

func MakeAuthorizeEndpoint(idp Provider) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		v, err := idp.InitAuthReq(request.(AuthRequest))
		return v, err
	}
}
