package oidc

import (
	"context"
	"net/http"
	"net/url"
	"strings"
)

// DecodeAuthorizeRequest is the DecodeRequestFunc for extracting the query
// into the domain object AuthorizeRequest
func DecodeAuthorizeRequest(_ context.Context, r *http.Request) (interface{}, error) {
	if err := r.ParseForm(); err != nil {
		return nil, err
	}

	if rURI, err := url.Parse(r.FormValue("redirect_uri")); err != nil {
		return nil, err
	} else {
		ar := AuthRequest{
			ResponseTypes: []string{r.FormValue("response_type")},
			ClientID:      r.FormValue("client_id"),
			RedirectURI:   rURI,
			Scopes:        strings.Split(r.FormValue("scope"), "+"),
			State:         r.FormValue("state"),
		}
		return ar, nil
	}
}

// EncodeAuthorizeResponse is the EncodeResponseFunc to pass the result
// to the caller
func EncodeAuthorizeResponse(_ context.Context, w http.ResponseWriter, response interface{}) error {
	h := w.Header()
	h.Set("Location", "http://localhost:3864/login")
	w.WriteHeader(http.StatusFound)
	return nil
}
