package oidc

import (
	"errors"
	"fmt"
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

// ResponseType values are specified in
// https://tools.ietf.org/html/rfc6749#section-3.1.1 and
// http://openid.net/specs/oauth-v2-multiple-response-types-1_0.html, respectively.
type ResponseType int

const (
	RT_CODE ResponseType = iota
	RT_TOKEN
	RT_IDTOKEN
	RT_NONE
	// error value
	RT_INVALID
)

//                          0    5     11       20   25     32
const _ResponseType_name = "code,token,id_token,none,invalid."

var _ResponseType_index = [...]uint8{0, 5, 11, 20, 25, 32}

func (i ResponseType) String() string {
	if i < 0 || i >= ResponseType(len(_ResponseType_index)-1) {
		return fmt.Sprintf("ResponseType(%d)", i)
	}
	return _ResponseType_name[_ResponseType_index[i] : _ResponseType_index[i+1]-1]
}

// AuthRequest takes oAuth2 Authorization Requests, as defined in
// https://tools.ietf.org/html/rfc6749#section-4.1.1, and OIDC Authentication Requests.
type AuthRequest struct {
	ResponseTypes []ResponseType `json:"response_types"`
	ClientID      string         `json:"client_id"`
	RedirectURI   *url.URL       `json:"redirect_uri",omitempty`
	Scopes        []string       `json:"scope",omitempty`
	State         string         `json:"state",omitempty`
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
	clientID, err := parseClientID(r.FormValue("client_id"))
	if err != nil {
		return nil, &Error{ERR_INVALID_REQUEST, err, ""}
	}
	ar := &AuthRequest{
		ResponseTypes: rt,
		ClientID:      clientID,
		RedirectURI:   redir,
		Scopes:        strings.Split(r.FormValue("scope"), "+"),
		State:         r.FormValue("state"),
	}
	return ar, nil
}

func parseResponseType(rawrt string) ([]ResponseType, error) {
	if rawrt == "" {
		return []ResponseType{RT_INVALID}, errors.New("missing response_type")
	}
	rt, err := url.QueryUnescape(rawrt)
	if err != nil {
		return []ResponseType{RT_INVALID}, errors.New("malformed response_type")
	}
	switch rt {
	case "code":
		return []ResponseType{RT_CODE}, nil
	case "token":
		return []ResponseType{RT_TOKEN}, nil
	case "id_token":
		return []ResponseType{RT_IDTOKEN}, nil
	case "code id_token":
		return []ResponseType{RT_CODE, RT_IDTOKEN}, nil
	case "id_token token":
		return []ResponseType{RT_IDTOKEN, RT_TOKEN}, nil
	case "code id_token token":
		return []ResponseType{RT_CODE, RT_IDTOKEN, RT_TOKEN}, nil
	case "none":
		return []ResponseType{RT_NONE}, nil
	default:
		return []ResponseType{RT_INVALID}, errors.New("unsupported response_type")
	}
}

func parseRedirectURI(rawuri string) (*url.URL, error) {
	if rawuri == "" {
		return nil, errors.New("missing redirect_uri")
	}
	rawredir, err := url.QueryUnescape(rawuri)
	if err != nil {
		return nil, err
	}
	u, e := url.ParseRequestURI(rawredir)
	return u, e
}

func parseClientID(ID string) (string, error) {
	if ID == "" {
		return "", errors.New("missing client_id")
	}
	return ID, nil
}

type Error struct {
	Code  string
	Err   error
	Debug string
}

func (e *Error) Error() string {
	/*	d := ""
		if len(e.Debug) == 0 {
			d = " [" + e.Debug + "]"
		}*/
	return e.Code + ": " + e.Err.Error() // + d
}

type LoginHint struct {
	AMR   string
	State string
}
