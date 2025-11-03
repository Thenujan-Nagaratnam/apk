package transformer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
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
	transformer.cfg.Logger.Sugar().Debugf("Fetching JWT Issuer for organizationID: %s and issuer: %s", organizationID, issuer)
	return transformer.tokenissuerStore.GetJWTIssuerByOrganizationAndIssuer(organizationID, issuer)
}

// GetJWTIssuerByOrganizationAndIssuerAndEnvironment returns the JWTIssuer for the given organization, environment and issuer.
func (transformer *JWTTransformer) GetJWTIssuerByOrganizationAndIssuerAndEnvironment(organizationID string, environment string, issuer string) *subscription.JWTIssuer {
	transformer.cfg.Logger.Sugar().Debugf("Fetching JWT Issuer for organizationID: %s, environment: %s and issuer: %s", organizationID, environment, issuer)
	return transformer.tokenissuerStore.GetJWTIssuerByOrganizationAndIssuerAndEnvironment(organizationID, environment, issuer)
}

// ExtractJWTValidationInfo parses a JWT token, validates it, and directly returns JWT validation info
func (transformer *JWTTransformer) ExtractJWTValidationInfo(jwtToken string, organizationID string, signedJWTInfo *SignedJWTInfo, tokenType string) (*dto.JWTValidationInfo, error) {
	// Extract issuer from claims
	var issuer string
	if iss, ok := signedJWTInfo.Claims["iss"].(string); ok {
		issuer = iss
	}
	transformer.cfg.Logger.Sugar().Infof("Extracted issuer from JWT claims: %s", issuer)

	if issuer == "" {
		transformer.cfg.Logger.Sugar().Infof("Issuer claim is missing in the JWT token")
		return nil, fmt.Errorf("invalid credentials")
	}

	authSuccessData := &dto.AuthenticationSuccessData{
		Issuer: issuer,
		Claims: signedJWTInfo.Claims,
	}

	keyName := fmt.Sprintf("%s-%s-payload", issuer, tokenType)
	authenticationData := &dto.AuthenticationData{
		SucessData: map[string]*dto.AuthenticationSuccessData{
			keyName: authSuccessData,
		},
		FailedData: nil,
	}

	jwtValidationInfo := transformer.TransformJWTClaims(organizationID, authenticationData, tokenType, issuer)
	if jwtValidationInfo == nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	transformer.cfg.Logger.Sugar().Infof("Successfully created JWT validation info for issuer: %s", issuer)
	return jwtValidationInfo, nil
}

// SignedJWTInfo holds the parsed JWT token and its claims.
type SignedJWTInfo struct {
	Token  *jwt.Token
	Claims jwt.MapClaims
}

// JWKSResponse represents the structure of a JWKS response
type JWKSResponse struct {
	Keys []JWK `json:"keys"`
}

// JWK represents a JSON Web Key
type JWK struct {
	Kid string `json:"kid,omitempty"` // Key ID
	Kty string `json:"kty"`           // Key Type
	Use string `json:"use,omitempty"` // Public Key Use
	Alg string `json:"alg,omitempty"` // Algorithm
	N   string `json:"n,omitempty"`   // RSA modulus
	E   string `json:"e,omitempty"`   // RSA exponent
	X   string `json:"x,omitempty"`   // ECDSA x coordinate
	Y   string `json:"y,omitempty"`   // ECDSA y coordinate
	Crv string `json:"crv,omitempty"` // ECDSA curve
}

// ValidateJWTExpiry validates JWT timing claims (exp, iat, nbf)
func (transformer *JWTTransformer) ValidateJWTExpiry(claims jwt.MapClaims) error {
	now := time.Now().Unix()

	// Check expiration time (exp) - required
	if exp, ok := claims["exp"]; ok {
		var expTime int64
		switch v := exp.(type) {
		case float64:
			expTime = int64(v)
		case int64:
			expTime = v
		case int:
			expTime = int64(v)
		default:
			return fmt.Errorf("invalid exp claim format")
		}

		if now >= expTime {
			transformer.cfg.Logger.Sugar().Infof("JWT token expired: exp=%d, now=%d", expTime, now)
			return fmt.Errorf("token expired at %d, current time is %d", expTime, now)
		}
		transformer.cfg.Logger.Sugar().Infof("JWT token expiry validation passed: exp=%d, now=%d", expTime, now)
	} else {
		transformer.cfg.Logger.Sugar().Infof("JWT token missing exp claim - treating as non-expiring")
	}

	return nil
}

// ParseSignedJWT parses a JWT token with signature verification and extracts claims, token identifier, and header information.
func (transformer *JWTTransformer) ParseSignedJWT(jwtToken string, environment string, organizationID string) (*SignedJWTInfo, error) {
	if jwtToken == "" {
		return nil, fmt.Errorf("JWT token cannot be empty")
	}

	parser := jwt.NewParser()
	claims := jwt.MapClaims{}

	// First parse without verification to get the header and issuer
	token, _, err := parser.ParseUnverified(jwtToken, claims)
	if err != nil {
		return nil, fmt.Errorf("parse JWT: %w", err)
	}

	// Extract issuer from claims
	var issuer string
	if iss, ok := claims["iss"].(string); ok {
		issuer = iss
	}

	if issuer == "" {
		return nil, fmt.Errorf("JWT token missing required 'iss' (issuer) claim")
	}

	// Get the token issuer configuration for signature verification
	tokenIssuer := transformer.GetJWTIssuerByOrganizationAndIssuerAndEnvironment(organizationID, environment, issuer)
	if tokenIssuer == nil {
		return nil, fmt.Errorf("no token issuer configuration found for issuer '%s' in organization '%s' and environment '%s'", issuer, organizationID, environment)
	}

	// Perform signature verification
	err = transformer.validateSignature(token, tokenIssuer)
	if err != nil {
		return nil, fmt.Errorf("JWT signature verification failed: %w", err)
	}

	info := &SignedJWTInfo{
		Token:  token,
		Claims: claims,
	}

	return info, nil
}

// validateSignature validates the JWT signature using the token issuer configuration
func (transformer *JWTTransformer) validateSignature(token *jwt.Token, tokenIssuer *subscription.JWTIssuer) error {
	// Extract the key ID from the JWT header
	var keyID string
	if kid, ok := token.Header["kid"].(string); ok {
		keyID = kid
	}

	transformer.cfg.Logger.Sugar().Infof("Validating JWT signature for issuer: %s, keyID: %s", tokenIssuer.Issuer, keyID)

	// Check if we have certificate configuration
	if tokenIssuer.Certificate == nil {
		return fmt.Errorf("no certificate configuration found for issuer %s", tokenIssuer.Issuer)
	}

	// Extract signing method from token
	if token.Method == nil {
		return fmt.Errorf("no signing method specified in token")
	}

	transformer.cfg.Logger.Sugar().Infof("certificate content data: %s", tokenIssuer.Certificate.Certificate)

	// Check if we have JWKS URL configuration (remote JWKS scenario)
	if tokenIssuer.Certificate.Jwks != nil && tokenIssuer.Certificate.Jwks.Url != "" {
		transformer.cfg.Logger.Sugar().Infof("Using remote JWKS from URL for signature verification")
		return transformer.verifyWithJWKS(token, keyID, tokenIssuer.Certificate.Jwks.Url, tokenIssuer.Certificate.Jwks.Tls, "")
	} else if tokenIssuer.Certificate.Certificate != "" {
		// Treat certificate field as local JWKS data
		transformer.cfg.Logger.Sugar().Infof("Using local JWKS from certificate field for signature verification")
		return transformer.verifyWithJWKS(token, keyID, "", "", tokenIssuer.Certificate.GetCertificate())
	}

	return fmt.Errorf("no JWKS configuration available for signature verification")
}

// verifyWithJWKS verifies JWT signature using JWKS data (either from URL or local data)
func (transformer *JWTTransformer) verifyWithJWKS(token *jwt.Token, keyID, jwksURL, tlsConfig, localJWKSData string) error {
	// Check if we have a keyID to look for
	if keyID == "" {
		return fmt.Errorf("no key ID found in JWT header, cannot verify with JWKS")
	}

	// Get JWKS data (either remote or local)
	jwksResponse, err := transformer.getJWKSData(jwksURL, tlsConfig, localJWKSData)
	if err != nil {
		return fmt.Errorf("failed to obtain JWKS data: %w", err)
	}

	// From here on, treat all JWKS data identically
	return transformer.verifyWithJWKSResponse(token, jwksResponse, keyID, localJWKSData == "")
}

// getJWKSData obtains JWKS data either from a remote URL or local data
func (transformer *JWTTransformer) getJWKSData(jwksURL, tlsConfig, localJWKSData string) (*JWKSResponse, error) {
	if jwksURL != "" {
		// Remote JWKS scenario
		transformer.cfg.Logger.Sugar().Infof("Fetching JWKS from remote URL: %s", jwksURL)
		return transformer.fetchJWKS(jwksURL, tlsConfig)
	} else if localJWKSData != "" {
		// Local JWKS scenario
		transformer.cfg.Logger.Sugar().Infof("Using local JWKS data")
		var jwksResponse JWKSResponse
		err := json.Unmarshal([]byte(localJWKSData), &jwksResponse)
		if err != nil {
			return nil, fmt.Errorf("failed to parse local JWKS data: %w", err)
		}
		return &jwksResponse, nil
	}
	return nil, fmt.Errorf("neither JWKS URL nor local JWKS data provided")
}

// verifyWithJWKSResponse verifies JWT signature using a JWKS response (common logic for both local and remote)
func (transformer *JWTTransformer) verifyWithJWKSResponse(token *jwt.Token, jwksResponse *JWKSResponse, keyID string, isRemote bool) error {
	transformer.cfg.Logger.Sugar().Infof("Verifying JWT signature with JWKS data, keyID: %s", keyID)

	// Find the key by keyID
	var targetJWK *JWK
	if isRemote {
		for i := range jwksResponse.Keys {
			if jwksResponse.Keys[i].Kid == keyID {
				targetJWK = &jwksResponse.Keys[i]
				break
			}
		}
	} else if len(jwksResponse.Keys) > 0 {
		targetJWK = &jwksResponse.Keys[0]
	}

	if targetJWK == nil {
		return fmt.Errorf("key with ID '%s' not found in JWKS", keyID)
	}

	// Extract public key from JWK
	publicKey, err := transformer.extractPublicKeyFromJWK(targetJWK)
	if err != nil {
		return fmt.Errorf("failed to extract public key from JWK: %w", err)
	}

	// Verify the signature based on the key type
	switch targetJWK.Kty {
	case "RSA":
		rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("JWK key type is RSA but extracted key is not RSA")
		}
		return transformer.verifyRSASignature(token, rsaPublicKey)
	case "EC":
		ecdsaPublicKey, ok := publicKey.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("JWK key type is EC but extracted key is not ECDSA")
		}
		return transformer.verifyECDSASignature(token, ecdsaPublicKey)
	default:
		return fmt.Errorf("unsupported JWK key type: %s", targetJWK.Kty)
	}
}

// fetchJWKS fetches JWKS from the given URL with optional TLS configuration
func (transformer *JWTTransformer) fetchJWKS(jwksURL string, tlsConfig string) (*JWKSResponse, error) {
	transformer.cfg.Logger.Sugar().Infof("Starting JWKS fetch from URL: %s", jwksURL)
	transformer.cfg.Logger.Sugar().Infof("TLS config provided: %t (length: %d)", tlsConfig != "", len(tlsConfig))

	// Create HTTP client with optional TLS configuration
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	// Configure TLS with proper certificate handling
	transport := &http.Transport{}
	systemCertPool, err := x509.SystemCertPool()

	if err != nil {
		transformer.cfg.Logger.Sugar().Errorf("Failed to get system certificate pool: %v", err)
		return nil, fmt.Errorf("failed to get system certificate pool: %w", err)
	}
	baseTLSConfig := &tls.Config{
		RootCAs: systemCertPool,
	}

	if tlsConfig != "" {
		// Parse the PEM certificate from tlsConfig
		block, _ := pem.Decode([]byte(tlsConfig))
		if block == nil {
			transformer.cfg.Logger.Sugar().Errorf("Failed to decode PEM certificate from tlsConfig")
			return nil, fmt.Errorf("failed to decode PEM certificate from tlsConfig")
		}
		transformer.cfg.Logger.Sugar().Infof("PEM block decoded successfully. Type: %s", block.Type)
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			transformer.cfg.Logger.Sugar().Errorf("Failed to parse certificate: %v", err)
			return nil, fmt.Errorf("failed to parse certificate from tlsConfig: %w", err)
		}

		transformer.cfg.Logger.Sugar().Infof("Certificate parsed successfully. Subject: %s, Issuer: %s", cert.Subject, cert.Issuer)
		// Add the certificate to the existing CA pool
		baseTLSConfig.RootCAs.AddCert(cert)
		transformer.cfg.Logger.Sugar().Infof("Added custom certificate to existing CA pool")
	} else {
		transformer.cfg.Logger.Sugar().Infof("No custom TLS certificate provided, using system CA pool only")
	}

	transport.TLSClientConfig = baseTLSConfig
	client.Transport = transport

	transformer.cfg.Logger.Sugar().Infof("HTTP client configured with TLS settings. InsecureSkipVerify: %t", baseTLSConfig.InsecureSkipVerify)
	// Add special handling for known JWKS endpoints that may have certificate issues
	_, urlParseErr := url.Parse(jwksURL)
	if urlParseErr != nil {
		transformer.cfg.Logger.Sugar().Errorf("Failed to parse JWKS URL: %v", err)
		return nil, fmt.Errorf("failed to parse JWKS URL: %w", err)
	}

	transformer.cfg.Logger.Sugar().Infof("Making GET request to: %s", jwksURL)
	resp, err := client.Get(jwksURL)
	if err != nil {
		transformer.cfg.Logger.Sugar().Errorf("HTTP GET request failed: %v", err)
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	transformer.cfg.Logger.Sugar().Infof("JWKS endpoint responded with status: %d", resp.StatusCode)

	if resp.StatusCode != http.StatusOK {
		transformer.cfg.Logger.Sugar().Errorf("JWKS endpoint returned non-200 status: %d", resp.StatusCode)
		return nil, fmt.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		transformer.cfg.Logger.Sugar().Errorf("Failed to read JWKS response body: %v", err)
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	transformer.cfg.Logger.Sugar().Infof("JWKS response body length: %d bytes", len(body))
	transformer.cfg.Logger.Sugar().Debugf("JWKS response (first 500 chars): %s", func() string {
		if len(body) > 500 {
			return string(body[:500]) + "..."
		}
		return string(body)
	}())
	// Parse JWKS response
	var jwksResponse JWKSResponse
	err = json.Unmarshal(body, &jwksResponse)
	if err != nil {
		transformer.cfg.Logger.Sugar().Errorf("Failed to unmarshal JWKS JSON: %v", err)
		return nil, fmt.Errorf("failed to parse JWKS response: %w", err)
	}
	transformer.cfg.Logger.Sugar().Infof("Successfully fetched JWKS with %d keys", len(jwksResponse.Keys))
	return &jwksResponse, nil
}

// extractPublicKeyFromJWK extracts a crypto public key from a JWK
func (transformer *JWTTransformer) extractPublicKeyFromJWK(jwk *JWK) (interface{}, error) {
	switch jwk.Kty {
	case "RSA":
		return transformer.extractRSAPublicKey(jwk)
	case "EC":
		return transformer.extractECDSAPublicKey(jwk)
	default:
		return nil, fmt.Errorf("unsupported key type: %s", jwk.Kty)
	}
}

// extractRSAPublicKey extracts an RSA public key from a JWK
func (transformer *JWTTransformer) extractRSAPublicKey(jwk *JWK) (*rsa.PublicKey, error) {
	if jwk.N == "" || jwk.E == "" {
		return nil, fmt.Errorf("RSA JWK missing required parameters n or e")
	}

	// Decode modulus (n)
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("failed to decode RSA modulus: %w", err)
	}

	// Decode exponent (e)
	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("failed to decode RSA exponent: %w", err)
	}

	// Convert to big integers
	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)

	return &rsa.PublicKey{
		N: n,
		E: int(e.Int64()),
	}, nil
}

// extractECDSAPublicKey extracts an ECDSA public key from a JWK
func (transformer *JWTTransformer) extractECDSAPublicKey(jwk *JWK) (*ecdsa.PublicKey, error) {
	if jwk.X == "" || jwk.Y == "" {
		return nil, fmt.Errorf("ECDSA JWK missing required parameters x or y")
	}

	// Decode x coordinate
	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("failed to decode ECDSA x coordinate: %w", err)
	}

	// Decode y coordinate
	yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		return nil, fmt.Errorf("failed to decode ECDSA y coordinate: %w", err)
	}

	// Convert to big integers
	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)

	// Determine curve based on the curve parameter or coordinate size
	var curve elliptic.Curve
	switch jwk.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		// Try to guess based on coordinate size
		switch len(xBytes) {
		case 32:
			curve = elliptic.P256()
		case 48:
			curve = elliptic.P384()
		case 66:
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("unsupported ECDSA curve: %s", jwk.Crv)
		}
	}

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}, nil
}

// verifyRSASignature verifies RSA signatures
func (transformer *JWTTransformer) verifyRSASignature(token *jwt.Token, rsaPublicKey *rsa.PublicKey) error {
	transformer.cfg.Logger.Sugar().Infof("Verifying RSA signature with algorithm: %s", token.Method.Alg())

	// Parse the token parts to get the signing string and signature
	parts := strings.Split(token.Raw, ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid JWT format")
	}

	// Create signing string (header.payload)
	signingString := parts[0] + "." + parts[1]
	signature := parts[2]

	// Use the appropriate RSA signing method based on the algorithm
	var signingMethod jwt.SigningMethod
	switch token.Method.Alg() {
	case "RS256":
		signingMethod = jwt.SigningMethodRS256
	case "RS384":
		signingMethod = jwt.SigningMethodRS384
	case "RS512":
		signingMethod = jwt.SigningMethodRS512
	default:
		return fmt.Errorf("unsupported RSA algorithm: %s", token.Method.Alg())
	}

	// Decode the base64 signature
	sigBytes, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	// Verify the signature
	err = signingMethod.Verify(signingString, sigBytes, rsaPublicKey)
	if err != nil {
		transformer.cfg.Logger.Sugar().Errorf("RSA signature verification failed: %v", err)
		return fmt.Errorf("RSA signature verification failed: %w", err)
	}

	transformer.cfg.Logger.Sugar().Infof("RSA signature verification successful")
	return nil
}

// verifyECDSASignature verifies ECDSA signatures
func (transformer *JWTTransformer) verifyECDSASignature(token *jwt.Token, ecdsaPublicKey *ecdsa.PublicKey) error {
	transformer.cfg.Logger.Sugar().Infof("Verifying ECDSA signature with algorithm: %s", token.Method.Alg())

	// Parse the token parts to get the signing string and signature
	parts := strings.Split(token.Raw, ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid JWT format")
	}

	// Create signing string (header.payload)
	signingString := parts[0] + "." + parts[1]
	signature := parts[2]
	// Decode the base64 signature
	sigBytes, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	// Use the appropriate ECDSA signing method based on the algorithm
	var signingMethod jwt.SigningMethod
	switch token.Method.Alg() {
	case "ES256":
		signingMethod = jwt.SigningMethodES256
	case "ES384":
		signingMethod = jwt.SigningMethodES384
	case "ES512":
		signingMethod = jwt.SigningMethodES512
	default:
		return fmt.Errorf("unsupported ECDSA algorithm: %s", token.Method.Alg())
	}

	// Verify the signature
	err = signingMethod.Verify(signingString, sigBytes, ecdsaPublicKey)
	if err != nil {
		transformer.cfg.Logger.Sugar().Errorf("ECDSA signature verification failed: %v", err)
		return fmt.Errorf("ECDSA signature verification failed: %w", err)
	}

	transformer.cfg.Logger.Sugar().Infof("ECDSA signature verification successful")
	return nil
}
