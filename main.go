package main

import (
	"context"
	"fmt"
	"os"

	"github.com/alecthomas/kong"
	"golang.org/x/oauth2"
)

// CLI is the root command struct
type CLI struct {
	// Base options
	Issuer         string `kong:"required,help='OIDC Issuer URL'"`
	ClientID       string `kong:"help='OIDC Client ID (required unless -register-client is set)'"`
	ClientSecret   string `kong:"help='OIDC Client Secret (required unless -register-client is set)'"`
	PortLow        int    `kong:"help='Lowest TCP port to bind on localhost for callbacks. By default, a port will be randomly assigned by the operating system.'"`
	PortHigh       int    `kong:"help='Highest TCP port to bind on localhost for callbacks. By default, a port will be randomly assigned by the operating system.'"`
	Offline        bool   `kong:"help='Offline use (request refresh token). This token will be cached locally, can be used to avoid re-launching the auth flow when the token expires'"`
	SkipCache      bool   `kong:"help='Do not perform any local caching on token'"`
	Scopes         string `kong:"help='Comma separated list of extra scopes to request'"`
	RegisterClient bool   `kong:"help='Perform dynamic client registration and use the returned client ID/secret'"`

	// Subcommands
	Raw        RawCmd        `kong:"cmd,help='Output a raw JWT for this client'"`
	Kubernetes KubernetesCmd `kong:"cmd,help='Output credentials in a format that can be consumed by kubectl/client-go'"`
	Info       InfoCmd       `kong:"cmd,help='Output information about the auth response in human-readable format'"`
}

func main() {
	// Create root context
	goCtx := context.Background()

	var cli CLI
	parser, err := kong.New(&cli)
	if err != nil {
		fmt.Printf("failed to create parser: %v\n", err)
		os.Exit(1)
	}

	ctx, err := parser.Parse(os.Args[1:])
	if err != nil {
		fmt.Printf("error: %v\n", err)
		os.Exit(1)
	}

	// Set up provider and token source once
	prov, ts, err := setupProviderAndTokenSource(goCtx, &cli)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		os.Exit(1)
	}

	ctx.BindTo(goCtx, (*context.Context)(nil))
	ctx.Bind(&cli)
	ctx.Bind(prov)
	ctx.BindTo(ts, (*oauth2.TokenSource)(nil))

	if err := ctx.Run(); err != nil {
		fmt.Printf("error: %+v\n", err)
		os.Exit(1)
	}
}
