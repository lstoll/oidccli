package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"lds.li/oauth2ext/clitoken"
	"lds.li/oauth2ext/jwt"
	"lds.li/oauth2ext/oauth2client"
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

	oa2Cfg := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     prov.Endpoint(),
		Scopes:       scopes,
	}
	clientType := oauth2client.PublicClient
	if clientSecret != "" {
		clientType = oauth2client.ConfidentialClient
	}
	clitokCfg := clitoken.Config{
		OAuth2Client: oa2Cfg,
		ClientType:   clientType,
		PortLow:      uint16(cli.PortLow),
		PortHigh:     uint16(cli.PortHigh),
	}

	cliTS, err := clitokCfg.TokenSource(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("getting cli token source: %w", err)
	}

	// The token cache is always used, as it manages the DPoP key for each
	// login. When caching is disabled it is only held in memory, but DPoP keys
	// still come from the platform store.
	log := slog.New(slog.DiscardHandler)
	if cli.Debug {
		log = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}

	var store tokencache.Store
	if ps := clitoken.PlatformStore(); ps != nil {
		store = ps
		log.Debug("using platform credential store", "type", fmt.Sprintf("%T", ps))
	} else {
		store = &clitoken.MemCredentialCache{}
		if cli.DPoP {
			fmt.Fprintln(os.Stderr, "warning: no hardware-backed credential store available, DPoP keys will be software keys held in memory")
		}
		log.Debug("no platform credential store available, using memory")
	}
	var cache tokencache.CredentialCache = store
	if skipCache {
		cache = &clitoken.MemCredentialCache{}
	}

	ccfg := tokencache.Config{
		Issuer: cli.Issuer,
		CacheKey: (tokencache.IDTokenCacheKey{
			ClientID: clientID,
			Scopes:   scopes,
		}).Key(),
		WrappedSource: cliTS,
		Cache:         cache,
		Logger:        log,
	}
	if cli.Offline {
		ccfg.TokenSourceProvider = oa2Cfg
	}
	if cli.DPoP {
		ccfg.DPoPKeys = store
	}

	ts, err := ccfg.TokenSource(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating token cache: %w", err)
	}

	return prov, ts, nil
}

// kubeToken represents the token in Kubernetes exec credential format
type kubeToken struct {
	Token               string     `json:"token,omitempty"`
	ExpirationTimestamp *time.Time `json:"expirationTimestamp,omitempty"`
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

	signingAlgorithms, err := provider.IDTokenSigningAlgorithms(ctx)
	if err != nil {
		return "", "", fmt.Errorf("getting supported ID token signing algorithms: %w", err)
	}
	if slices.Contains(signingAlgorithms, jwt.ES256) {
		request.IDTokenSignedResponseAlg = "ES256"
	}

	response, err := oidcclientreg.RegisterWithProvider(ctx, provider, request)
	if err != nil {
		return "", "", fmt.Errorf("failed to register client: %w", err)
	}

	return response.ClientID, response.ClientSecret, nil
}
