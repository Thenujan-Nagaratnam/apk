package authenticator

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/wso2/apk/adapter/pkg/discovery/api/wso2/discovery/subscription"
	"github.com/wso2/apk/gateway/enforcer/internal/config"
	"github.com/wso2/apk/gateway/enforcer/internal/datastore"
	"github.com/wso2/apk/gateway/enforcer/internal/dto"
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

// NewOAuth2Authenticator creates a new OAuth2Authenticator.
func NewOAuth2Authenticator(jwtTransformer *transformer.JWTTransformer, revokedJTIStore *datastore.RevokedJTIStore, mandatory bool, cfg *config.Server) *OAuth2Authenticator {
	return &OAuth2Authenticator{jwtTransformer: jwtTransformer, mandatory: mandatory, revokedJTIStore: revokedJTIStore, cfg: cfg}
}

const (
	// Oauth2AuthType is the Oauth2 authentication type.
	Oauth2AuthType = "oauth2"
)

// Authenticate performs the authentication.
func (authenticator *OAuth2Authenticator) Authenticate(rch *requestconfig.Holder) AuthenticationResponse {
	if rch == nil {
		authenticator.cfg.Logger.Sugar().Infof("Request config holder is nil")
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
		authenticator.cfg.Logger.Sugar().Infof("Authorization header is missing")
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
		authenticator.cfg.Logger.Sugar().Infof("Bearer token is missing in the authorization header")
		return AuthenticationResponse{
			Authenticated:               false,
			MandatoryAuthentication:     authenticator.mandatory,
			ErrorCode:                   InvalidCredentials,
			ErrorMessage:                InvalidCredentialsMessage,
			ContinueToNextAuthenticator: !authenticator.mandatory,
		}
	}

	if jwtToken == "" {
		authenticator.cfg.Logger.Sugar().Infof("JWT token cannot be empty")
		return AuthenticationResponse{
			Authenticated:               false,
			MandatoryAuthentication:     authenticator.mandatory,
			ErrorCode:                   InvalidCredentials,
			ErrorMessage:                InvalidCredentialsMessage,
			ContinueToNextAuthenticator: !authenticator.mandatory,
		}
	}

	// Parse the JWT token to extract claims and token info
	signedJWTInfo, err := authenticator.parseSignedJWT(jwtToken, rch.MatchedAPI.OrganizationID)
	if err != nil {
		authenticator.cfg.Logger.Sugar().Infof("Error parsing JWT token: %v", err)
		return AuthenticationResponse{
			Authenticated:               false,
			MandatoryAuthentication:     authenticator.mandatory,
			ErrorCode:                   InvalidCredentials,
			ErrorMessage:                InvalidCredentialsMessage,
			ContinueToNextAuthenticator: !authenticator.mandatory,
		}
	}

	// Check JWT expiry
	err = authenticator.validateJWTExpiry(signedJWTInfo.Claims)
	if err != nil {
		authenticator.cfg.Logger.Sugar().Infof("JWT token expired or invalid timing: %v", err)
		return AuthenticationResponse{
			Authenticated:               false,
			MandatoryAuthentication:     authenticator.mandatory,
			ErrorCode:                   ExpiredToken,
			ErrorMessage:                ExpiredTokenMessage,
			ContinueToNextAuthenticator: !authenticator.mandatory,
		}
	}

	// Parse and validate the JWT token directly
	jwtValidationInfo, err := authenticator.extractJWTValidationInfo(jwtToken, rch.MatchedAPI.OrganizationID, signedJWTInfo)
	if err != nil || jwtValidationInfo == nil {
		authenticator.cfg.Logger.Sugar().Infof("Error parsing and validating JWT token: %v", err)
		return AuthenticationResponse{
			Authenticated:               false,
			MandatoryAuthentication:     authenticator.mandatory,
			ErrorCode:                   InvalidCredentials,
			ErrorMessage:                InvalidCredentialsMessage,
			ContinueToNextAuthenticator: !authenticator.mandatory,
		}
	}

	// Check for revoked tokens and validate
	authenticator.cfg.Logger.Sugar().Infof("JWT validation info: %+v", jwtValidationInfo)
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
		rch.JWTValidationInfo = jwtValidationInfo
		rch.AuthenticatedAuthenticationType = Oauth2AuthType
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

func getOAuth2Header(rch *requestconfig.Holder) string {
	for _, header := range rch.Request.GetRequestHeaders().GetHeaders().Headers {
		if header.Key == rch.MatchedResource.AuthenticationConfig.Oauth2AuthenticationConfig.Header {
			return string(header.RawValue)
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

// extractJWTValidationInfo parses a JWT token, validates it, and directly returns JWT validation info
func (authenticator *OAuth2Authenticator) extractJWTValidationInfo(jwtToken string, organizationID string, signedJWTInfo *SignedJWTInfo) (*dto.JWTValidationInfo, error) {

	// Extract issuer from claims
	var issuer string
	if iss, ok := signedJWTInfo.Claims["iss"].(string); ok {
		issuer = iss
	}
	authenticator.cfg.Logger.Sugar().Infof("Extracted issuer from JWT claims: %s", issuer)

	if issuer == "" {
		authenticator.cfg.Logger.Sugar().Infof("Issuer claim is missing in the JWT token")
		return nil, fmt.Errorf(InvalidCredentialsMessage)
	}

	authSuccessData := &dto.AuthenticationSuccessData{
		Issuer: issuer,
		Claims: signedJWTInfo.Claims,
	}

	keyName := fmt.Sprintf("%s-%s-payload", issuer, Oauth2AuthType)
	authenticationData := &dto.AuthenticationData{
		SucessData: map[string]*dto.AuthenticationSuccessData{
			keyName: authSuccessData,
		},
		FailedData: nil,
	}

	jwtValidationInfo := authenticator.jwtTransformer.TransformJWTClaims(organizationID, authenticationData, Oauth2AuthType, issuer)
	if jwtValidationInfo == nil {
		return nil, fmt.Errorf(InvalidCredentialsMessage)
	}

	authenticator.cfg.Logger.Sugar().Infof("Successfully created JWT validation info for issuer: %s", issuer)
	return jwtValidationInfo, nil
}

// validateJWTExpiry validates JWT timing claims (exp, iat, nbf)
func (authenticator *OAuth2Authenticator) validateJWTExpiry(claims jwt.MapClaims) error {
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
			authenticator.cfg.Logger.Sugar().Infof("JWT token expired: exp=%d, now=%d", expTime, now)
			return fmt.Errorf("token expired at %d, current time is %d", expTime, now)
		}
		authenticator.cfg.Logger.Sugar().Infof("JWT token expiry validation passed: exp=%d, now=%d", expTime, now)
	} else {
		authenticator.cfg.Logger.Sugar().Infof("JWT token missing exp claim - treating as non-expiring")
	}

	// Check not before time (nbf) - optional
	if nbf, ok := claims["nbf"]; ok {
		var nbfTime int64
		switch v := nbf.(type) {
		case float64:
			nbfTime = int64(v)
		case int64:
			nbfTime = v
		case int:
			nbfTime = int64(v)
		default:
			return fmt.Errorf("invalid nbf claim format")
		}

		if now < nbfTime {
			authenticator.cfg.Logger.Sugar().Infof("JWT token not yet valid: nbf=%d, now=%d", nbfTime, now)
			return fmt.Errorf("token not valid before %d, current time is %d", nbfTime, now)
		}
		authenticator.cfg.Logger.Sugar().Infof("JWT token nbf validation passed: nbf=%d, now=%d", nbfTime, now)
	}

	// Check issued at time (iat) - optional, just for logging
	if iat, ok := claims["iat"]; ok {
		var iatTime int64
		switch v := iat.(type) {
		case float64:
			iatTime = int64(v)
		case int64:
			iatTime = v
		case int:
			iatTime = int64(v)
		default:
			authenticator.cfg.Logger.Sugar().Warnf("Invalid iat claim format, ignoring")
		}

		if iatTime > 0 {
			authenticator.cfg.Logger.Sugar().Infof("JWT token issued at: %d (current time: %d)", iatTime, now)
		}
	}

	return nil
}

// parseSignedJWT parses a JWT token with signature verification and extracts claims, token identifier, and header information.
func (authenticator *OAuth2Authenticator) parseSignedJWT(jwtToken string, organizationID string) (*SignedJWTInfo, error) {
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
	tokenIssuer := authenticator.jwtTransformer.GetJWTIssuerByOrganizationAndIssuer(organizationID, issuer)
	if tokenIssuer == nil {
		return nil, fmt.Errorf("no token issuer configuration found for issuer '%s' in organization '%s'", issuer, organizationID)
	}

	// Perform signature verification
	err = authenticator.validateSignature(token, tokenIssuer)
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
func (authenticator *OAuth2Authenticator) validateSignature(token *jwt.Token, tokenIssuer *subscription.JWTIssuer) error {
	// Extract the key ID from the JWT header
	var keyID string
	if kid, ok := token.Header["kid"].(string); ok {
		keyID = kid
	}

	authenticator.cfg.Logger.Sugar().Infof("Validating JWT signature for issuer: %s, keyID: %s", tokenIssuer.Issuer, keyID)

	// Check if we have certificate configuration
	if tokenIssuer.Certificate == nil {
		return fmt.Errorf("no certificate configuration found for issuer %s", tokenIssuer.Issuer)
	}

	// Extract signing method from token
	if token.Method == nil {
		return fmt.Errorf("no signing method specified in token")
	}

	authenticator.cfg.Logger.Sugar().Infof("certificate content data: %s", tokenIssuer.Certificate.Certificate)

	// Check if we have JWKS URL configuration (remote JWKS scenario)
	if tokenIssuer.Certificate.Jwks != nil && tokenIssuer.Certificate.Jwks.Url != "" {
		authenticator.cfg.Logger.Sugar().Infof("Using remote JWKS from URL for signature verification")
		return authenticator.verifyWithJWKS(token, keyID, tokenIssuer.Certificate.Jwks.Url, tokenIssuer.Certificate.Jwks.Tls, "")
	} else if tokenIssuer.Certificate.Certificate != "" {
		// Treat certificate field as local JWKS data
		authenticator.cfg.Logger.Sugar().Infof("Using local JWKS from certificate field for signature verification")
		return authenticator.verifyWithJWKS(token, keyID, "", "", tokenIssuer.Certificate.GetCertificate())
	}

	return fmt.Errorf("no JWKS configuration available for signature verification")
}

// verifyWithJWKS verifies JWT signature using JWKS data (either from URL or local data)
func (authenticator *OAuth2Authenticator) verifyWithJWKS(token *jwt.Token, keyID, jwksURL, tlsConfig, localJWKSData string) error {
	// Check if we have a keyID to look for
	if keyID == "" {
		return fmt.Errorf("no key ID found in JWT header, cannot verify with JWKS")
	}

	// Get JWKS data (either remote or local)
	jwksResponse, err := authenticator.getJWKSData(jwksURL, tlsConfig, localJWKSData)
	if err != nil {
		return fmt.Errorf("failed to obtain JWKS data: %w", err)
	}

	// From here on, treat all JWKS data identically
	return authenticator.verifyWithJWKSResponse(token, jwksResponse, keyID, localJWKSData == "")
}

// getJWKSData obtains JWKS data either from a remote URL or local data
func (authenticator *OAuth2Authenticator) getJWKSData(jwksURL, tlsConfig, localJWKSData string) (*JWKSResponse, error) {
	if jwksURL != "" {
		// Remote JWKS scenario
		authenticator.cfg.Logger.Sugar().Infof("Fetching JWKS from remote URL: %s", jwksURL)
		return authenticator.fetchJWKS(jwksURL, tlsConfig)
	} else if localJWKSData != "" {
		// Local JWKS scenario
		authenticator.cfg.Logger.Sugar().Infof("Using local JWKS data")
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
func (authenticator *OAuth2Authenticator) verifyWithJWKSResponse(token *jwt.Token, jwksResponse *JWKSResponse, keyID string, isRemote bool) error {
	authenticator.cfg.Logger.Sugar().Infof("Verifying JWT signature with JWKS data, keyID: %s", keyID)

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
	publicKey, err := authenticator.extractPublicKeyFromJWK(targetJWK)
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
		return authenticator.verifyRSASignature(token, rsaPublicKey)
	case "EC":
		ecdsaPublicKey, ok := publicKey.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("JWK key type is EC but extracted key is not ECDSA")
		}
		return authenticator.verifyECDSASignature(token, ecdsaPublicKey)
	default:
		return fmt.Errorf("unsupported JWK key type: %s", targetJWK.Kty)
	}
}

// fetchJWKS fetches JWKS from the given URL with optional TLS configuration
func (authenticator *OAuth2Authenticator) fetchJWKS(url string, tlsConfig string) (*JWKSResponse, error) {
	authenticator.cfg.Logger.Sugar().Infof("Fetching JWKS from URL: %s", url)

	// Create HTTP client with optional TLS configuration
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	// Configure TLS with proper certificate handling
	// Always set up a transport with TLS config
	transport := &http.Transport{}

	// Get base TLS config from datastore
	baseTLSConfig, err := datastore.GetTLSConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to get base TLS config: %w", err)
	}

	// If additional certificate is provided, add it to the trusted certs
	if tlsConfig != "" {
		// Parse the PEM certificate from tlsConfig
		block, _ := pem.Decode([]byte(tlsConfig))
		if block == nil {
			return nil, fmt.Errorf("failed to decode PEM certificate from tlsConfig")
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate from tlsConfig: %w", err)
		}

		// Add the certificate to the existing CA pool
		if baseTLSConfig.RootCAs != nil {
			baseTLSConfig.RootCAs.AddCert(cert)
		} else {
			// Create new cert pool if none exists
			baseTLSConfig.RootCAs = x509.NewCertPool()
			baseTLSConfig.RootCAs.AddCert(cert)
		}

		authenticator.cfg.Logger.Sugar().Infof("Added custom certificate to trusted certs for JWKS endpoint")
	}

	transport.TLSClientConfig = baseTLSConfig
	client.Transport = transport

	// Make HTTP request to fetch JWKS
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Parse JWKS response
	var jwksResponse JWKSResponse
	err = json.Unmarshal(body, &jwksResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWKS response: %w", err)
	}

	authenticator.cfg.Logger.Sugar().Infof("Successfully fetched JWKS with %d keys", len(jwksResponse.Keys))
	return &jwksResponse, nil
}

// extractPublicKeyFromJWK extracts a crypto public key from a JWK
func (authenticator *OAuth2Authenticator) extractPublicKeyFromJWK(jwk *JWK) (interface{}, error) {
	switch jwk.Kty {
	case "RSA":
		return authenticator.extractRSAPublicKey(jwk)
	case "EC":
		return authenticator.extractECDSAPublicKey(jwk)
	default:
		return nil, fmt.Errorf("unsupported key type: %s", jwk.Kty)
	}
}

// extractRSAPublicKey extracts an RSA public key from a JWK
func (authenticator *OAuth2Authenticator) extractRSAPublicKey(jwk *JWK) (*rsa.PublicKey, error) {
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
func (authenticator *OAuth2Authenticator) extractECDSAPublicKey(jwk *JWK) (*ecdsa.PublicKey, error) {
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

// verifyWithCertificate verifies JWT signature using a certificate or JWKS data
func (authenticator *OAuth2Authenticator) verifyWithCertificate(token *jwt.Token, certData string) error {
	authenticator.cfg.Logger.Sugar().Infof("Verifying JWT signature with certificate")
	authenticator.cfg.Logger.Sugar().Infof("Certificate data: %s", certData)

	var cert *x509.Certificate
	var err error

	// Try to parse as PEM first
	if block, _ := pem.Decode([]byte(certData)); block != nil {
		// It's PEM encoded
		cert, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse PEM certificate: %w", err)
		}
	} else {
		// Try to parse as base64 encoded DER
		certBytes, err := base64.StdEncoding.DecodeString(certData)
		if err != nil {
			// If base64 decoding fails, try treating it as raw DER bytes
			certBytes = []byte(certData)
		}

		cert, err = x509.ParseCertificate(certBytes)
		if err != nil {
			return fmt.Errorf("failed to parse certificate (tried PEM, base64 DER, and raw DER): %w", err)
		}
	}

	// Extract the public key from the certificate
	publicKey := cert.PublicKey

	// Verify the signature based on the algorithm
	switch token.Method.Alg() {
	case "RS256", "RS384", "RS512":
		rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("certificate does not contain RSA public key")
		}
		return authenticator.verifyRSASignature(token, rsaPublicKey)
	case "ES256", "ES384", "ES512":
		ecdsaPublicKey, ok := publicKey.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("certificate does not contain ECDSA public key")
		}
		return authenticator.verifyECDSASignature(token, ecdsaPublicKey)
	case "none":
		authenticator.cfg.Logger.Sugar().Warnf("JWT token has no signature (alg: none)")
		return nil
	default:
		return fmt.Errorf("unsupported signing algorithm: %s", token.Method.Alg())
	}
}

// verifyRSASignature verifies RSA signatures
func (authenticator *OAuth2Authenticator) verifyRSASignature(token *jwt.Token, rsaPublicKey *rsa.PublicKey) error {
	authenticator.cfg.Logger.Sugar().Infof("Verifying RSA signature with algorithm: %s", token.Method.Alg())

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

	// Verify the signature
	err := signingMethod.Verify(signingString, signature, rsaPublicKey)
	if err != nil {
		authenticator.cfg.Logger.Sugar().Errorf("RSA signature verification failed: %v", err)
		return fmt.Errorf("RSA signature verification failed: %w", err)
	}

	authenticator.cfg.Logger.Sugar().Infof("RSA signature verification successful")
	return nil
}

// verifyECDSASignature verifies ECDSA signatures
func (authenticator *OAuth2Authenticator) verifyECDSASignature(token *jwt.Token, ecdsaPublicKey *ecdsa.PublicKey) error {
	authenticator.cfg.Logger.Sugar().Infof("Verifying ECDSA signature with algorithm: %s", token.Method.Alg())

	// Parse the token parts to get the signing string and signature
	parts := strings.Split(token.Raw, ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid JWT format")
	}

	// Create signing string (header.payload)
	signingString := parts[0] + "." + parts[1]
	signature := parts[2]

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
	err := signingMethod.Verify(signingString, signature, ecdsaPublicKey)
	if err != nil {
		authenticator.cfg.Logger.Sugar().Errorf("ECDSA signature verification failed: %v", err)
		return fmt.Errorf("ECDSA signature verification failed: %w", err)
	}

	authenticator.cfg.Logger.Sugar().Infof("ECDSA signature verification successful")
	return nil
}

// verifyWithJWKSData verifies JWT signature using JWKS data in string format
func (authenticator *OAuth2Authenticator) verifyWithJWKSData(token *jwt.Token, jwksData string) error {
	authenticator.cfg.Logger.Sugar().Infof("Verifying JWT signature with JWKS data")

	// Extract the key ID from the JWT header
	var keyID string
	if kid, ok := token.Header["kid"].(string); ok {
		keyID = kid
	}

	if keyID == "" {
		return fmt.Errorf("no key ID found in JWT header, cannot verify with JWKS")
	}

	// Parse JWKS data from JSON string
	var jwksResponse JWKSResponse
	err := json.Unmarshal([]byte(jwksData), &jwksResponse)
	if err != nil {
		return fmt.Errorf("failed to parse JWKS data: %w", err)
	}

	// Find the key by keyID
	var targetJWK *JWK
	for i := range jwksResponse.Keys {
		if jwksResponse.Keys[i].Kid == keyID {
			targetJWK = &jwksResponse.Keys[i]
			break
		}
	}

	if targetJWK == nil {
		return fmt.Errorf("key with ID '%s' not found in JWKS", keyID)
	}

	// Extract public key from JWK
	publicKey, err := authenticator.extractPublicKeyFromJWK(targetJWK)
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
		return authenticator.verifyRSASignature(token, rsaPublicKey)
	case "EC":
		ecdsaPublicKey, ok := publicKey.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("JWK key type is EC but extracted key is not ECDSA")
		}
		return authenticator.verifyECDSASignature(token, ecdsaPublicKey)
	default:
		return fmt.Errorf("unsupported JWK key type: %s", targetJWK.Kty)
	}
}
