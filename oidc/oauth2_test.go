package oidc

import (
	"errors"
	"net/http"
	"net/url"
	"testing"
)

func TestParseAuthRequest(t *testing.T) {
	var tests = []struct {
		sample *http.Request
		want   *AuthRequest
		err    *Error
	}{
		{ // happy case
			&http.Request{Method: "GET", URL: mustParseURL("http://login.example.com/oauth/authorize?response_type=code&client_id=client1&redirect_uri=http://example.com/cb&scope=read&state=state-1234")},
			&AuthRequest{[]string{"code"}, "client1", mustParseURL("http://example.com/cb"), []string{"read"}, "state-1234"},
			nil,
		},
		{ // no query
			&http.Request{Method: "GET", URL: mustParseURL("http://login.example.com/oauth/authorize")},
			&AuthRequest{[]string{"code"}, "client1", mustParseURL("http://example.com/cb"), []string{"read"}, "state-1234"},
			&Error{Code: ERR_INVALID_REQUEST, Err: errors.New("missing redirect_uri")},
		},
	}
	for _, test := range tests {
		got, err := ParseAuthRequest(test.sample)
		if err != nil {
			t.Logf(err.Error())
			if err.Code != test.err.Code || err.Error() != test.err.Error() {
				t.Errorf("ParseAuthRequest(%q) = _, %v; got _,%v", test.sample.URL, test.err, err)
			}
			break
		}
		if got.State != test.want.State {
			t.Errorf("ParseAuthRequest(%q) = %v, got %v", test.sample.URL, test.want.State, got.State)
		}
	}
}

func mustParseURL(r string) *url.URL {
	u, _ := url.Parse(r)
	return u
}
