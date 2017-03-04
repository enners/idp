package oidc

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
)

const (
	ERR_INVALID_REQUEST     = "invalid_request"
	ERR_UNAUTHORIZED_CLIENT = "unauthorized_client"
)

// AuthRequest takes oAuth2 Authorization Requests, as defined in
// https://tools.ietf.org/html/rfc6749#section-4.1.1, and OIDC Authentication Requests.
type AuthRequest struct {
	ResponseTypes []string `json:"response_type"`
	ClientID      string   `json:"client_id"`
	RedirectURI   *url.URL `json:"redirect_uri",omitempty`
	Scopes        []string `json:"scope",omitempty`
	State         string   `json:"state",omitempty`
}

// ParseAuthRequest parses r into an AuthRequest structure.
func ParseAuthRequest(r *http.Request) (*AuthRequest, *Error) {
	if err := r.ParseForm(); err != nil {
		return nil, &Error{ERR_INVALID_REQUEST, err}
	}
	redir, err := parseRedirectURI(r.FormValue("redirect_uri"))
	if err != nil {
		return nil, &Error{ERR_INVALID_REQUEST, err}
	}
	return &AuthRequest{
		ResponseTypes: strings.Split(r.FormValue("response_type"), "+"),
		ClientID:      r.FormValue("client_id"),
		RedirectURI:   redir,
		Scopes:        strings.Split(r.FormValue("scope"), "+"),
		State:         r.FormValue("state"),
	}, nil
}

func parseRedirectURI(rawuri string) (*url.URL, error) {
	if rawuri == "" {
		return nil, errors.New("missing redirect_uri")
	}
	rawredir, err := url.QueryUnescape(rawuri)
	if err != nil {
		return nil, err
	}
	u, e := url.Parse(rawredir)
	return u, e
}

type Error struct {
	Code string
	Err  error
}

func (e *Error) Error() string {
	return e.Code + ": " + e.Err.Error()
}

type LoginHint struct {
	AMR   string
	State string
}
