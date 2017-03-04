package oidc

import ()

type Client struct {
	Name          string
	ID            string
	Secret        string
	RedirectURLs  []string
	ResponseTypes []string
	GrantTypes    []string
	LogoURL       string
}

type ClientService interface {
	Load(ID string) (Client, error)
}
