package main

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"lds.li/oauth2ext/clitoken"
	"lds.li/oauth2ext/dpop"
	"lds.li/oauth2ext/oidc"
	"lds.li/oauth2ext/oidcclientreg"
	"lds.li/oauth2ext/provider"
	"lds.li/oauth2ext/tokencache"
)

// setupProviderAndTokenSource sets up the OIDC provider and token source based on CLI options
func setupProviderAndTokenSource(ctx context.Context, cli *CLI) (*provider.Provider, oauth2.TokenSource, error) {
	// Validate flag combinations
	if cli.RegisterClient {
		if cli.ClientID != "" || cli.ClientSecret != "" {
			return nil, nil, fmt.Errorf("-register-client cannot be used with -client-id or -client-secret")
		}
	} else {
		if cli.ClientID == "" {
			return nil, nil, fmt.Errorf("client-id is required (unless -register-client is set)")
		}
	}

	prov, err := provider.DiscoverOIDCProvider(ctx, cli.Issuer)
	if err != nil {
		return nil, nil, fmt.Errorf("discovering issuer %s: %w", cli.Issuer, err)
	}

	clientID := cli.ClientID
	clientSecret := cli.ClientSecret
	skipCache := cli.SkipCache

	// Perform dynamic client registration if requested
	if cli.RegisterClient {
		registeredClientID, registeredClientSecret, err := registerClient(ctx, prov)
		if err != nil {
			return nil, nil, fmt.Errorf("registering client: %w", err)
		}

		// Print the client credentials
		fmt.Printf("Client ID: %s\n", registeredClientID)
		if registeredClientSecret != "" {
			fmt.Printf("Client Secret: %s\n", registeredClientSecret)
		}

		// Use the registered client credentials
		clientID = registeredClientID
		clientSecret = registeredClientSecret
		// We always create a new client, so caching doesn't help.
		skipCache = true
	}

	scopes := []string{oidc.ScopeOpenID}
	if cli.Offline {
		scopes = append(scopes, oidc.ScopeOfflineAccess)
	}
	if cli.Scopes != "" {
		scopes = append(scopes, strings.Split(cli.Scopes, ",")...)
	}

	oa2Cfg := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     prov.Endpoint(),
		Scopes:       scopes,
	}
	clitokCfg := clitoken.Config{
		OAuth2Config: oa2Cfg,
		PortLow:      uint16(cli.PortLow),
		PortHigh:     uint16(cli.PortHigh),
	}

	if cli.DPoP {
		signer, err := clitoken.BestSigner()
		if err != nil {
			return nil, nil, fmt.Errorf("getting best signer: %w", err)
		}

		dpopSigner, err := dpop.NewSigner(signer)
		if err != nil {
			return nil, nil, fmt.Errorf("creating dpop encoder: %w", err)
		}

		dpopTransport := &dpop.Transport{
			Base:   http.DefaultTransport,
			Signer: dpopSigner,
		}

		ctx = context.WithValue(ctx, oauth2.HTTPClient, &http.Client{
			Transport: dpopTransport,
		})
	}

	ts, err := clitokCfg.TokenSource(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("getting cli token source: %w", err)
	}

	if !skipCache {
		ccfg := tokencache.Config{
			Issuer: cli.Issuer,
			CacheKey: (tokencache.IDTokenCacheKey{
				ClientID: clientID,
				Scopes:   scopes,
			}).Key(),
			WrappedSource: ts,
			Cache:         clitoken.BestCredentialCache(),
		}
		if cli.Offline {
			ccfg.OAuth2Config = &oa2Cfg
		}

		ts, err = ccfg.TokenSource(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("error creating token cache: %w", err)
		}
	}

	return prov, ts, nil
}

// kubeToken represents the token in Kubernetes exec credential format
type kubeToken struct {
	Token               string     `json:"token,omitempty"`
	ExpirationTimestamp *time.Time `json:"expirationTimestamp,omitempty"`
}

// isJWT guesses if something is a JWT
func isJWT(s string) bool {
	return strings.Count(s, ".") == 2
}

// registerClient performs dynamic client registration with the OIDC provider
func registerClient(ctx context.Context, provider *provider.Provider) (string, string, error) {
	// Create registration request
	request := &oidcclientreg.ClientRegistrationRequest{
		RedirectURIs:    []string{"http://127.0.0.1/callback"},
		ApplicationType: "native",
		ResponseTypes:   []string{"code"},
		GrantTypes:      []string{"authorization_code"},
	}

	if slices.Contains(provider.IDTokenSigningAlgValuesSupported(), "ES256") {
		request.IDTokenSignedResponseAlg = "ES256"
	}

	response, err := oidcclientreg.RegisterWithProvider(ctx, provider, request)
	if err != nil {
		return "", "", fmt.Errorf("failed to register client: %w", err)
	}

	return response.ClientID, response.ClientSecret, nil
}
