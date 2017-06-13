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
	ERR_ACCESS_DENIED       = "access_denied"
	ERR_RESPONSE_TYPE       = "unsupported_response_type"
	ERR_INVALID_SCOPE       = "invalid_scope"
	ERR_SERVER              = "server_error"
	ERR_UNAVAILABLE         = "temporarily_unavailable"
)

// AuthRequest takes oAuth2 Authorization Requests, as defined in
// https://tools.ietf.org/html/rfc6749#section-4.1.1, and OIDC Authentication Requests.
type AuthRequest struct {
	ResponseType string   `json:"response_type"`
	ClientID     string   `json:"client_id"`
	RedirectURI  *url.URL `json:"redirect_uri",omitempty`
	Scopes       []string `json:"scope",omitempty`
	State        string   `json:"state",omitempty`
}

// ParseAuthRequest parses r into an AuthRequest structure.
func ParseAuthRequest(r *http.Request) (*AuthRequest, *Error) {
	if err := r.ParseForm(); err != nil {
		return nil, &Error{ERR_INVALID_REQUEST, err, ""}
	}
	rt, err := parseResponseType(r.FormValue("response_type"))
	if err != nil {
		return nil, &Error{ERR_INVALID_REQUEST, err, ""}
	}
	redir, err := parseRedirectURI(r.FormValue("redirect_uri"))
	if err != nil {
		return nil, &Error{ERR_INVALID_REQUEST, err, ""}
	}
	return &AuthRequest{
		ResponseType: rt,
		ClientID:     r.FormValue("client_id"),
		RedirectURI:  redir,
		Scopes:       strings.Split(r.FormValue("scope"), "+"),
		State:        r.FormValue("state"),
	}, nil
}

func parseResponseType(rawrt string) (string, error) {
	if rawrt == "" {
		return rawrt, errors.New("missing response_type")
	}
	return url.QueryUnescape(rawrt)
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
	Code  string
	Err   error
	Debug string
}

func (e *Error) Error() string {
	d := ""
	if len(e.Debug) == 0 {
		d = " [" + e.Debug + "]"
	}
	return e.Code + ": " + e.Err.Error() + d
}

type LoginHint struct {
	AMR   string
	State string
}
