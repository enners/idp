package oidc

import (
	"context"
	"fmt"
	"net/http"
	//	"net/url"
	//	"strings"
)

// DecodeAuthorizeRequest is the DecodeRequestFunc for extracting the query
// into the domain object AuthorizeRequest
func DecodeAuthorizeRequest(_ context.Context, r *http.Request) (interface{}, error) {
	ar, err := ParseAuthRequest(r)
	if err != nil {
		return nil, err
	}
	return *ar, nil
}

// EncodeAuthorizeResponse is the EncodeResponseFunc to pass the result
// to the caller
func EncodeAuthorizeResponse(_ context.Context, w http.ResponseWriter, response interface{}) error {
	defer fmt.Printf("encoding response ... \n")
	h := w.Header()
	h.Set("Location", "http://localhost:3864/login")
	w.WriteHeader(http.StatusFound)
	return nil
}
