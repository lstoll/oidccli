package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"syscall"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/sts/types"
	"golang.org/x/oauth2"
	"lds.li/oauth2ext/clitoken"
	"lds.li/oauth2ext/oidc"
)

// AwsCmd is the root AWS command
type AwsCmd struct {
	RoleARN         string      `env:"OIDCCLI_AWS_ROLE_ARN" required:"" help:"AWS IAM Role ARN to assume"`
	Region          string      `env:"AWS_REGION" required:"" help:"AWS region"`
	SessionName     string      `help:"Session name for the assumed role (defaults to oidccli)"`
	DurationSeconds int32       `help:"Duration in seconds for the temporary credentials (default: 3600)"`
	Login           AwsLoginCmd `cmd:"" help:"Generate a temporary AWS console login URL and open it"`
	Exec            AwsExecCmd  `cmd:"" help:"Set AWS credentials as environment variables and execute a command"`
}

// AwsLoginCmd generates a temporary AWS console login URL
type AwsLoginCmd struct{}

// AwsExecCmd sets AWS credentials and executes a command
type AwsExecCmd struct {
	Command []string `arg:"" help:"Command to execute"`
}

// Run executes the AWS login command
func (a *AwsLoginCmd) Run(ctx context.Context, ts oauth2.TokenSource, awsCmd *AwsCmd) error {
	creds, err := assumeRoleWithWebIdentity(ctx, ts, awsCmd.RoleARN, awsCmd.getSessionName(), awsCmd.DurationSeconds, awsCmd.Region)
	if err != nil {
		return fmt.Errorf("assuming role: %w", err)
	}

	// Generate console sign-in URL (partition is derived from role ARN for correct sign-in endpoint)
	partition := partitionFromARN(awsCmd.RoleARN)
	consoleURL, err := generateConsoleSignInURL(creds, partition)
	if err != nil {
		return fmt.Errorf("generating console URL: %w", err)
	}

	fmt.Printf("Opening AWS console: %s\n", consoleURL)

	opener := clitoken.DetectOpener()
	if err := opener.Open(ctx, consoleURL); err != nil {
		return fmt.Errorf("opening console URL: %w", err)
	}

	return nil
}

// Run executes the AWS exec command
func (a *AwsExecCmd) Run(ctx context.Context, ts oauth2.TokenSource, awsCmd *AwsCmd) error {
	if len(a.Command) == 0 {
		return fmt.Errorf("no command provided after --")
	}

	creds, err := assumeRoleWithWebIdentity(ctx, ts, awsCmd.RoleARN, awsCmd.getSessionName(), awsCmd.DurationSeconds, awsCmd.Region)
	if err != nil {
		return fmt.Errorf("assuming role: %w", err)
	}

	// Find the executable
	execPath, err := exec.LookPath(a.Command[0])
	if err != nil {
		return fmt.Errorf("finding executable %s: %w", a.Command[0], err)
	}

	// Set environment variables
	os.Setenv("AWS_ACCESS_KEY_ID", *creds.AccessKeyId)
	os.Setenv("AWS_SECRET_ACCESS_KEY", *creds.SecretAccessKey)
	os.Setenv("AWS_SESSION_TOKEN", *creds.SessionToken)
	os.Setenv("AWS_SECURITY_TOKEN", *creds.SessionToken) // Some tools use this instead
	os.Setenv("AWS_REGION", awsCmd.Region)
	os.Setenv("AWS_DEFAULT_REGION", awsCmd.Region) // Some tools use this instead

	if err := syscall.Exec(execPath, a.Command, os.Environ()); err != nil {
		return fmt.Errorf("executing command: %w", err)
	}
	return nil
}

// assumeRoleWithWebIdentity assumes an AWS role using the OIDC JWT
func assumeRoleWithWebIdentity(ctx context.Context, ts oauth2.TokenSource, roleARN, sessionName string, durationSeconds int32, region string) (*types.Credentials, error) {
	// Get the OIDC token
	tok, err := ts.Token()
	if err != nil {
		return nil, fmt.Errorf("fetching token: %w", err)
	}

	// Get the ID token (JWT)
	idToken, ok := oidc.GetIDToken(tok)
	if !ok {
		return nil, fmt.Errorf("response has no id_token")
	}

	// Create STS client with no credentials (we'll use web identity)
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("loading AWS config: %w", err)
	}

	stsClient := sts.NewFromConfig(cfg)

	// Set default duration if not specified
	if durationSeconds == 0 {
		durationSeconds = 3600
	}

	// Call AssumeRoleWithWebIdentity
	input := &sts.AssumeRoleWithWebIdentityInput{
		RoleArn:          aws.String(roleARN),
		RoleSessionName:  aws.String(sessionName),
		WebIdentityToken: aws.String(idToken),
		DurationSeconds:  aws.Int32(durationSeconds),
	}

	result, err := stsClient.AssumeRoleWithWebIdentity(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("assuming role with web identity: %w", err)
	}

	return result.Credentials, nil
}

// partitionEndpoints maps AWS partition IDs to their sign-in and console federation endpoints.
// Each partition has its own sign-in service; using the wrong partition's endpoint will fail.
var partitionEndpoints = map[string]struct {
	Signin  string
	Console string
}{
	"aws":        {"signin.aws.amazon.com", "console.aws.amazon.com"},
	"aws-us-gov": {"signin.amazonaws-us-gov.com", "console.amazonaws-us-gov.com"},
	"aws-cn":     {"signin.amazonaws.cn", "console.amazonaws.cn"},
	"aws-eusc":   {"eusc-de-east-1.signin.amazonaws-eusc.eu", "console.amazonaws-eusc.eu"}, // TODO - pass region here.
}

// partitionFromARN extracts the partition from an AWS ARN using the SDK parser.
func partitionFromARN(roleARN string) string {
	parsed, err := arn.Parse(roleARN)
	if err != nil {
		return "aws"
	}
	return parsed.Partition
}

// generateConsoleSignInURL generates a temporary AWS console sign-in URL.
// The partition determines which sign-in federation endpoint to use (e.g., aws vs aws-eusc for EU sovereign cloud).
func generateConsoleSignInURL(creds *types.Credentials, partition string) (string, error) {
	eps, ok := partitionEndpoints[partition]
	if !ok {
		return "", fmt.Errorf("unsupported AWS partition %q for console sign-in", partition)
	}

	// Create a sign-in token request
	signinTokenReq := map[string]string{
		"sessionId":    aws.ToString(creds.AccessKeyId),
		"sessionKey":   aws.ToString(creds.SecretAccessKey),
		"sessionToken": aws.ToString(creds.SessionToken),
	}

	jsonBytes, err := json.Marshal(signinTokenReq)
	if err != nil {
		return "", fmt.Errorf("marshaling sign-in token request: %w", err)
	}

	// Get sign-in token from the partition-specific federation endpoint
	signinTokenURL := fmt.Sprintf("https://%s/federation?Action=getSigninToken&Session=%s", eps.Signin, url.QueryEscape(string(jsonBytes)))

	resp, err := http.Get(signinTokenURL)
	if err != nil {
		return "", fmt.Errorf("getting sign-in token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var signinTokenResp struct {
		SigninToken string `json:"SigninToken"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&signinTokenResp); err != nil {
		return "", fmt.Errorf("decoding sign-in token response: %w", err)
	}

	// Generate console URL using partition-specific destination
	destination := fmt.Sprintf("https://%s/", eps.Console)
	consoleURL := fmt.Sprintf("https://%s/federation?Action=login&Destination=%s&SigninToken=%s", eps.Signin, url.QueryEscape(destination), url.QueryEscape(signinTokenResp.SigninToken))

	return consoleURL, nil
}

// getSessionName returns the session name, defaulting to "oidccli" if not set
func (a *AwsCmd) getSessionName() string {
	if a.SessionName == "" {
		return "oidccli"
	}
	return a.SessionName
}
