package transformer

import (
	"strings"

	"github.com/wso2/apk/adapter/pkg/discovery/api/wso2/discovery/subscription"
	"github.com/wso2/apk/gateway/enforcer/internal/config"
	"github.com/wso2/apk/gateway/enforcer/internal/datastore"
	"github.com/wso2/apk/gateway/enforcer/internal/dto"
)

// JWTTransformer represents the JWT transformer.
type JWTTransformer struct {
	tokenissuerStore *datastore.JWTIssuerStore
	cfg              *config.Server
}

// NewJWTTransformer creates a new instance of JWTIssuerStore.
func NewJWTTransformer(cfg *config.Server, jwtIssuerDatastore *datastore.JWTIssuerStore) *JWTTransformer {
	return &JWTTransformer{cfg: cfg, tokenissuerStore: jwtIssuerDatastore}
}

// TransformJWTClaims transforms the JWT claims
func (transformer *JWTTransformer) TransformJWTClaims(organization string, jwtAuthenticationData *dto.AuthenticationData, tokenType string, issuer string) *dto.JWTValidationInfo {
	if jwtAuthenticationData == nil {
		return nil
	}
	tokenIssuer := transformer.tokenissuerStore.GetJWTIssuerByOrganizationAndIssuer(organization, issuer)
	transformer.cfg.Logger.Sugar().Infof("Token issuers for organization %s: %v", organization, tokenIssuer)
	if tokenIssuer == nil {
		return nil
	}
	var jwtValidationInfoSuccess *dto.JWTValidationInfo
	var jwtValidationInfoFailure *dto.JWTValidationInfo
	jwtAuthenticationDataSuccess, exists := jwtAuthenticationData.SucessData[issuer+"-"+tokenType+"-payload"]
	if exists {
		jwtValidationInfoSuccess = &dto.JWTValidationInfo{Valid: true, Issuer: jwtAuthenticationDataSuccess.Issuer, Claims: make(map[string]interface{})}
		remoteClaims := jwtAuthenticationDataSuccess.Claims
		if remoteClaims != nil {
			issuedTime := remoteClaims["iat"]
			if issuedTime != nil {
				jwtValidationInfoSuccess.IssuedTime = int64(issuedTime.(float64))
			}
			expiryTime := remoteClaims["exp"]
			if expiryTime != nil {
				jwtValidationInfoSuccess.ExpiryTime = int64(expiryTime.(float64))
			}
			jti := remoteClaims["jti"]
			if jti != nil {
				jwtValidationInfoSuccess.JTI = jti.(string)
			}
			audienceClaim := remoteClaims["aud"]
			if audienceClaim != nil {
				switch audienceClaim.(type) {
				case string:
					audiences := []string{remoteClaims["aud"].(string)}
					jwtValidationInfoSuccess.Audiences = audiences
				case []string:
					audiences := remoteClaims["aud"].([]string)
					jwtValidationInfoSuccess.Audiences = audiences
				}
			}
			remoteScopes := remoteClaims[tokenIssuer.ScopesClaim]
			if remoteScopes != nil {
				switch remoteScopes := remoteScopes.(type) {
				case string:
					scopes := strings.Split(remoteScopes, " ")
					jwtValidationInfoSuccess.Scopes = scopes
				case []string:
					scopes := remoteScopes
					jwtValidationInfoSuccess.Scopes = scopes
				}
			}
			remoteClientID := remoteClaims[tokenIssuer.ConsumerKeyClaim]
			if remoteClientID != nil {
				jwtValidationInfoSuccess.ClientID = remoteClientID.(string)
			}
			for claimKey, claimValue := range remoteClaims {
				if localClaim, ok := tokenIssuer.ClaimMapping[claimKey]; ok {
					jwtValidationInfoSuccess.Claims[localClaim] = claimValue
				} else {
					jwtValidationInfoSuccess.Claims[claimKey] = claimValue
				}
			}
		}
		transformer.cfg.Logger.Sugar().Infof("JWT validation success for the issuer %s", jwtValidationInfoSuccess)
		return jwtValidationInfoSuccess
	}
	jwtAuthenticationDataFailure, exists := jwtAuthenticationData.FailedData[tokenIssuer.Issuer+"-"+tokenType+"-failed"]
	if exists {
		jwtValidationInfoFailure = &dto.JWTValidationInfo{Valid: false, ValidationCode: jwtAuthenticationDataFailure.Code, ValidationMessage: jwtAuthenticationDataFailure.Message}
	} else {
		jwtAuthenticationDataFailure, exists := jwtAuthenticationData.FailedData["unknown-"+tokenType+"-failed"]
		if exists {
			jwtValidationInfoFailure = &dto.JWTValidationInfo{Valid: false, ValidationCode: jwtAuthenticationDataFailure.Code, ValidationMessage: jwtAuthenticationDataFailure.Message}
		}
	}
	if jwtValidationInfoFailure != nil {
		return jwtValidationInfoFailure
	}
	return nil
}

// GetTokenIssuerCount obtains the total token issuer count for metrics purposes.
func (transformer *JWTTransformer) GetTokenIssuerCount() int {
	return transformer.tokenissuerStore.GetJWTIssuerCount()
}

// GetJWTIssuerByOrganizationAndIssuer returns the JWTIssuer for the given organization and issuer.
func (transformer *JWTTransformer) GetJWTIssuerByOrganizationAndIssuer(organizationID string, issuer string) *subscription.JWTIssuer {
	return transformer.tokenissuerStore.GetJWTIssuerByOrganizationAndIssuer(organizationID, issuer)
}
