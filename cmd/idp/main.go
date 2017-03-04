package main

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/ennersk/idp/mock"
	"github.com/ennersk/idp/oidc"
	httpkit "github.com/go-kit/kit/transport/http"
)

func main() {
	ctx := context.Background()
	cs := mock.ClientSvc{}
	idp := oidc.NewProvider(oidc.ProviderConfig{
		ClientService: cs,
	})

	authorizeHandler := httpkit.NewServer(
		ctx,
		oidc.MakeAuthorizeEndpoint(idp),
		oidc.DecodeAuthorizeRequest,
		oidc.EncodeAuthorizeResponse)

	http.Handle("/authorize", authorizeHandler)

	fmt.Println("open your browser at http://localhost:3846")
	log.Fatal(http.ListenAndServe(":3846", nil))
}
