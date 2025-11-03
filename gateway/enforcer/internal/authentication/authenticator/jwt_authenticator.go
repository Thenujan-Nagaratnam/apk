package authenticator

import (
	"github.com/wso2/apk/gateway/enforcer/internal/config"
	"github.com/wso2/apk/gateway/enforcer/internal/datastore"
	"github.com/wso2/apk/gateway/enforcer/internal/requestconfig"
	"github.com/wso2/apk/gateway/enforcer/internal/transformer"
)

// JWTAuthenticator is the main authenticator.
type JWTAuthenticator struct {
	mandatory       bool
	jwtTransformer  *transformer.JWTTransformer
	revokedJTIStore *datastore.RevokedJTIStore
	cfg             *config.Server
}

// NewJWTAuthenticator creates a new JWTAuthenticator.
func NewJWTAuthenticator(jwtTransformer *transformer.JWTTransformer, revokedJTIStore *datastore.RevokedJTIStore, mandatory bool, cfg *config.Server) *JWTAuthenticator {
	return &JWTAuthenticator{jwtTransformer: jwtTransformer, mandatory: mandatory, revokedJTIStore: revokedJTIStore, cfg: cfg}
}

const (
	// JWTAuthType is the JWT authentication type.
	JWTAuthType = "jwt"
)

// Authenticate performs the authentication.
func (authenticator *JWTAuthenticator) Authenticate(rch *requestconfig.Holder) AuthenticationResponse {
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

	// Extract JWT token from request headers
	jwtToken := getJWTHeader(rch)
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
	signedJWTInfo, err := authenticator.jwtTransformer.ParseSignedJWT(jwtToken, rch.MatchedAPI.OrganizationID)
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
	jwtValidationInfo, err := authenticator.jwtTransformer.ExtractJWTValidationInfo(jwtToken, rch.MatchedAPI.OrganizationID, signedJWTInfo, JWTAuthType)
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
			ContinueToNextAuthenticator: !authenticator.mandatory,
		}
	}

	if jwtValidationInfo.Valid {
		audiencesFromToken := jwtValidationInfo.Audiences
		if len(audiencesFromToken) > 0 {
			authenticator.cfg.Logger.Sugar().Debugf("JWT token audiences: %v", audiencesFromToken)
			audiencesFromAPI := rch.MatchedResource.AuthenticationConfig.JWTAuthenticationConfig.Audience
			if !checkAnyExists(audiencesFromAPI, audiencesFromToken) {
				authenticator.cfg.Logger.Sugar().Debugf("JWT token audience validation failed. Token audiences: %v, Expected audiences: %v", audiencesFromToken, audiencesFromAPI)
				return AuthenticationResponse{
					Authenticated:               false,
					MandatoryAuthentication:     authenticator.mandatory,
					ErrorCode:                   InvalidCredentials,
					ErrorMessage:                InvalidCredentialsMessage,
					ContinueToNextAuthenticator: !authenticator.mandatory,
				}
			}
		}
		rch.JWTValidationInfo = jwtValidationInfo
		rch.AuthenticatedAuthenticationType = JWTAuthType
		return AuthenticationResponse{
			Authenticated:               true,
			MandatoryAuthentication:     authenticator.mandatory,
			ErrorCode:                   InvalidCredentials,
			ErrorMessage:                InvalidCredentialsMessage,
			ContinueToNextAuthenticator: !authenticator.mandatory,
		}
	}

	return AuthenticationResponse{
		Authenticated:               false,
		MandatoryAuthentication:     authenticator.mandatory,
		ContinueToNextAuthenticator: !authenticator.mandatory,
		ErrorCode:                   InvalidCredentials,
		ErrorMessage:                InvalidCredentialsMessage,
	}
}

func checkAnyExists(audiencesFromAPI []string, audiencesFromToken []string) bool {
	// If audiencesFromAPI is null or empty, return true
	if len(audiencesFromAPI) == 0 {
		return true
	}

	// Check if at least one element in audiencesFromAPI exists in audiencesFromToken
	for _, apiAudience := range audiencesFromAPI {
		for _, tokenAudience := range audiencesFromToken {
			if apiAudience == tokenAudience {
				return true
			}
		}
	}

	return false
}

func getJWTHeader(rch *requestconfig.Holder) string {
	for _, header := range rch.Request.GetRequestHeaders().GetHeaders().Headers {
		if header.Key == rch.MatchedResource.AuthenticationConfig.JWTAuthenticationConfig.Header {
			return string(header.RawValue)
		}
	}
	return ""
}
