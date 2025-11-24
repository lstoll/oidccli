package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/alecthomas/kong"
	"golang.org/x/oauth2"
	"lds.li/oauth2ext/clitoken"
	"lds.li/oauth2ext/oidc"
	"lds.li/oauth2ext/oidcclientreg"
	"lds.li/oauth2ext/provider"
	"lds.li/oauth2ext/tokencache"
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

// RawCmd outputs a raw JWT token
type RawCmd struct {
	UseAccessToken bool            `kong:"help='Use access token, rather than id_token'"`
	CLI            *CLI            `kong:"-"`
	Context        context.Context `kong:"-"`
}

// Run executes the raw command
func (r *RawCmd) Run(ctx *kong.Context) error {
	provider, ts, err := setupProviderAndTokenSource(r.Context, r.CLI)
	if err != nil {
		return err
	}
	_ = provider // not used in raw command

	tok, err := ts.Token()
	if err != nil {
		return fmt.Errorf("fetching token: %v", err)
	}
	raw := tok.AccessToken
	if !r.UseAccessToken {
		idt, ok := oidc.GetIDToken(tok)
		if !ok {
			return fmt.Errorf("response has no id_token")
		}
		raw = idt
	}
	fmt.Print(raw)
	return nil
}

// KubernetesCmd outputs credentials in Kubernetes exec credential format
type KubernetesCmd struct {
	UseAccessToken bool            `kong:"help='Use access token, rather than id_token'"`
	CLI            *CLI            `kong:"-"`
	Context        context.Context `kong:"-"`
}

// Run executes the kubernetes command
func (k *KubernetesCmd) Run(ctx *kong.Context) error {
	provider, ts, err := setupProviderAndTokenSource(k.Context, k.CLI)
	if err != nil {
		return err
	}
	_ = provider // not used in kubernetes command

	tok, err := ts.Token()
	if err != nil {
		return fmt.Errorf("fetching token: %v", err)
	}
	var raw = tok.AccessToken
	if !k.UseAccessToken {
		idt, ok := oidc.GetIDToken(tok)
		if !ok {
			return fmt.Errorf("response has no id_token")
		}
		raw = idt
	}
	creds := kubeExecCred{
		APIVersion: apiVersion,
		Kind:       execCredKind,
		Status: kubeToken{
			Token:               raw,
			ExpirationTimestamp: &tok.Expiry,
		},
	}
	return json.NewEncoder(os.Stdout).Encode(&creds)
}

// InfoCmd outputs information about the auth response
type InfoCmd struct {
	CLI     *CLI            `kong:"-"`
	Context context.Context `kong:"-"`
}

// Run executes the info command
func (i *InfoCmd) Run(ctx *kong.Context) error {
	prov, ts, err := setupProviderAndTokenSource(i.Context, i.CLI)
	if err != nil {
		return err
	}

	tok, err := ts.Token()
	if err != nil {
		return fmt.Errorf("fetching token: %v", err)
	}

	fmt.Printf("Access Token: %s\n", tok.AccessToken)
	fmt.Printf("Access Token expires: %s\n", tok.Expiry.String())
	if isJWT(tok.AccessToken) {
		// TODO - add access token verification
	}
	fmt.Printf("Refresh Token: %s\n", tok.RefreshToken)
	idt, ok := oidc.GetIDToken(tok)
	if ok {
		validator, err := prov.NewIDTokenValidator(&provider.IDTokenValidatorOpts{
			IgnoreClientID: true,
		})
		if err != nil {
			return fmt.Errorf("creating id token validator: %w", err)
		}
		claims, err := prov.VerifyAndDecodeIDToken(tok, validator)
		if err != nil {
			return fmt.Errorf("ID token verification: %w", err)
		}

		clJSON, err := claims.JSONPayload()
		if err != nil {
			return fmt.Errorf("getting id token json payload: %w", err)
		}

		allClaims := make(map[string]any)
		if err := json.Unmarshal(clJSON, &allClaims); err != nil {
			return fmt.Errorf("unmarshalling id token claims: %w", err)
		}

		clJSON, err = json.MarshalIndent(allClaims, "", "  ")
		if err != nil {
			return fmt.Errorf("marshalling id token claims: %w", err)
		}

		exp, err := claims.ExpiresAt()
		if err != nil {
			return fmt.Errorf("getting id token expires at: %w", err)
		}

		fmt.Printf("ID token: %s\n", idt)
		fmt.Printf("ID token expires at: %s\n", exp)
		fmt.Printf("ID token claims: \n%s\n", string(clJSON))
	}

	return nil
}

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
		scopes = append(scopes, "offline")
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

const (
	apiVersion   = "client.authentication.k8s.io/v1beta1"
	execCredKind = "ExecCredential"
)

// kubeExecCred represents the Kubernetes exec credential response
type kubeExecCred struct {
	APIVersion string    `json:"apiVersion,omitempty"`
	Kind       string    `json:"kind,omitempty"`
	Status     kubeToken `json:"status"`
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

	if slices.Contains(provider.Metadata.GetIDTokenSigningAlgValuesSupported(), "ES256") {
		request.IDTokenSignedResponseAlg = "ES256"
	}

	response, err := oidcclientreg.RegisterWithProvider(ctx, provider, request)
	if err != nil {
		return "", "", fmt.Errorf("failed to register client: %w", err)
	}

	return response.ClientID, response.ClientSecret, nil
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

	// Set the CLI reference and context on each subcommand so they can access base options
	cli.Raw.CLI = &cli
	cli.Raw.Context = goCtx
	cli.Kubernetes.CLI = &cli
	cli.Kubernetes.Context = goCtx
	cli.Info.CLI = &cli
	cli.Info.Context = goCtx

	// Kong will automatically call the Run method on the selected command
	if err := ctx.Run(); err != nil {
		fmt.Printf("error: %+v\n", err)
		os.Exit(1)
	}
}
