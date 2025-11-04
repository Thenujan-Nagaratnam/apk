package authenticator

import (
	"strings"

	"github.com/wso2/apk/gateway/enforcer/internal/config"
	"github.com/wso2/apk/gateway/enforcer/internal/datastore"
	"github.com/wso2/apk/gateway/enforcer/internal/requestconfig"
	"github.com/wso2/apk/gateway/enforcer/internal/transformer"
)

// OAuth2Authenticator is the main authenticator.
type OAuth2Authenticator struct {
	mandatory       bool
	jwtTransformer  *transformer.JWTTransformer
	revokedJTIStore *datastore.RevokedJTIStore
	cfg             *config.Server
}

// NewOAuth2Authenticator creates a new OAuth2Authenticator.
func NewOAuth2Authenticator(jwtTransformer *transformer.JWTTransformer, revokedJTIStore *datastore.RevokedJTIStore, mandatory bool, cfg *config.Server) *OAuth2Authenticator {
	return &OAuth2Authenticator{jwtTransformer: jwtTransformer, mandatory: mandatory, revokedJTIStore: revokedJTIStore, cfg: cfg}
}

const (
	// OAuth2AuthType is the Oauth2 authentication type.
	OAuth2AuthType = "oauth2"
)

// Authenticate performs the authentication.
func (authenticator *OAuth2Authenticator) Authenticate(rch *requestconfig.Holder) AuthenticationResponse {
	if rch == nil {
		authenticator.cfg.Logger.Sugar().Debugf("Request config holder is nil")
		return AuthenticationResponse{
			Authenticated:               false,
			MandatoryAuthentication:     authenticator.mandatory,
			ErrorCode:                   MissingCredentials,
			ErrorMessage:                MissingCredentialsMesage,
			ContinueToNextAuthenticator: !authenticator.mandatory,
		}
	}

	// Extract OAuth2 token from request headers
	authHeader := getOAuth2Header(rch)
	if authHeader == "" {
		authenticator.cfg.Logger.Sugar().Debugf("Authorization header is missing")
		return AuthenticationResponse{
			Authenticated:               false,
			MandatoryAuthentication:     authenticator.mandatory,
			ErrorCode:                   MissingCredentials,
			ErrorMessage:                MissingCredentialsMesage,
			ContinueToNextAuthenticator: !authenticator.mandatory,
		}
	}

	// Extract Bearer token from the authorization header
	jwtToken, found := extractBearerToken(authHeader)
	if !found || jwtToken == "" {
		authenticator.cfg.Logger.Sugar().Debugf("Bearer token is missing in the authorization header")
		return AuthenticationResponse{
			Authenticated:               false,
			MandatoryAuthentication:     authenticator.mandatory,
			ErrorCode:                   InvalidCredentials,
			ErrorMessage:                InvalidCredentialsMessage,
			ContinueToNextAuthenticator: !authenticator.mandatory,
		}
	}

	if jwtToken == "" {
		authenticator.cfg.Logger.Sugar().Debugf("JWT token cannot be empty")
		return AuthenticationResponse{
			Authenticated:               false,
			MandatoryAuthentication:     authenticator.mandatory,
			ErrorCode:                   InvalidCredentials,
			ErrorMessage:                InvalidCredentialsMessage,
			ContinueToNextAuthenticator: !authenticator.mandatory,
		}
	}

	// Parse the JWT token to extract claims and token info
	signedJWTInfo, err := authenticator.jwtTransformer.ParseSignedJWT(jwtToken, rch.MatchedAPI.Environment, rch.MatchedAPI.OrganizationID)
	if err != nil {
		authenticator.cfg.Logger.Sugar().Debugf("Error parsing JWT token: %v", err)
		return AuthenticationResponse{
			Authenticated:               false,
			MandatoryAuthentication:     authenticator.mandatory,
			ErrorCode:                   InvalidCredentials,
			ErrorMessage:                InvalidCredentialsMessage,
			ContinueToNextAuthenticator: !authenticator.mandatory,
		}
	}

	// Check JWT expiry
	err = authenticator.jwtTransformer.ValidateJWTExpiry(signedJWTInfo.Claims)
	if err != nil {
		authenticator.cfg.Logger.Sugar().Debugf("JWT token expired or invalid timing: %v", err)
		return AuthenticationResponse{
			Authenticated:               false,
			MandatoryAuthentication:     authenticator.mandatory,
			ErrorCode:                   ExpiredToken,
			ErrorMessage:                ExpiredTokenMessage,
			ContinueToNextAuthenticator: !authenticator.mandatory,
		}
	}

	// Parse and validate the JWT token directly
	jwtValidationInfo, err := authenticator.jwtTransformer.ExtractJWTValidationInfo(jwtToken, rch.MatchedAPI.OrganizationID, signedJWTInfo, OAuth2AuthType)
	if err != nil || jwtValidationInfo == nil {
		authenticator.cfg.Logger.Sugar().Debugf("Error parsing and validating JWT token: %v", err)
		return AuthenticationResponse{
			Authenticated:               false,
			MandatoryAuthentication:     authenticator.mandatory,
			ErrorCode:                   InvalidCredentials,
			ErrorMessage:                InvalidCredentialsMessage,
			ContinueToNextAuthenticator: !authenticator.mandatory,
		}
	}

	// Check for revoked tokens and validate
	authenticator.cfg.Logger.Sugar().Debugf("JWT validation info: %+v", jwtValidationInfo)
	if authenticator.revokedJTIStore != nil && authenticator.revokedJTIStore.IsJTIRevoked(jwtValidationInfo.JTI) {
		return AuthenticationResponse{
			Authenticated:               false,
			MandatoryAuthentication:     authenticator.mandatory,
			ErrorCode:                   ExpiredToken,
			ErrorMessage:                ExpiredTokenMessage,
			ContinueToNextAuthenticator: false,
		}
	}

	if jwtValidationInfo.Valid {
		rch.JWTValidationInfo = jwtValidationInfo
		rch.AuthenticatedAuthenticationType = OAuth2AuthType
		return AuthenticationResponse{
			Authenticated:               true,
			MandatoryAuthentication:     authenticator.mandatory,
			ErrorCode:                   InvalidCredentials,
			ErrorMessage:                InvalidCredentialsMessage,
			ContinueToNextAuthenticator: false,
		}
	}

	return AuthenticationResponse{
		Authenticated:               false,
		MandatoryAuthentication:     authenticator.mandatory,
		ContinueToNextAuthenticator: false,
		ErrorCode:                   InvalidCredentials,
		ErrorMessage:                InvalidCredentialsMessage,
	}
}

func getOAuth2Header(rch *requestconfig.Holder) string {
	if rch != nil && rch.Request != nil && rch.Request.GetRequestHeaders() != nil && rch.Request.GetRequestHeaders().GetHeaders() != nil && rch.Request.GetRequestHeaders().GetHeaders().Headers != nil {
		for _, header := range rch.Request.GetRequestHeaders().GetHeaders().Headers {
			if header.Key == rch.MatchedResource.AuthenticationConfig.Oauth2AuthenticationConfig.Header {
				return string(header.RawValue)
			}
		}
	}
	return ""
}

func extractBearerToken(authHeader string) (string, bool) {
	if authHeader == "" {
		return "", false
	}
	parts := strings.Fields(authHeader) // splits on any whitespace
	if len(parts) >= 2 && strings.EqualFold(parts[0], "Bearer") {
		return parts[1], true
	}
	return "", false
}
