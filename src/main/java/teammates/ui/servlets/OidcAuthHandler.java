package teammates.ui.servlets;

import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import com.nimbusds.openid.connect.sdk.SubjectType;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;

import teammates.common.util.Logger;

/**
 * Handles the full OIDC Authorization Code Flow for a single configured provider.
 *
 * <p>One instance is created per provider during servlet {@code init()} and reused for all
 * requests.  {@link RemoteJWKSet} is thread-safe and automatically refreshes signing keys
 * when an unknown {@code kid} is encountered.
 */
class OidcAuthHandler {

    private static final Logger log = Logger.getLogger();

    private final OidcProviderConfig config;
    private final OIDCProviderMetadata metadata;
    private final JWKSource<SecurityContext> jwkSource;

    OidcAuthHandler(OidcProviderConfig config) throws IOException {
        this.config = config;
        boolean anyOverride = config.authorizationEndpointOverride != null
                || config.tokenEndpointOverride != null
                || config.jwksEndpointOverride != null;
        if (anyOverride) {
            // Manual mode: all three overrides must be present
            if (config.authorizationEndpointOverride == null
                    || config.tokenEndpointOverride == null
                    || config.jwksEndpointOverride == null) {
                throw new IOException("Provider '" + config.id + "': when any endpoint override is set, "
                        + "all three overrides (authorization, token, jwks) must be set.");
            }
            try {
                URI authUri = new URI(config.authorizationEndpointOverride);
                URI tokenUri = new URI(config.tokenEndpointOverride);
                URI jwksUri = new URI(config.jwksEndpointOverride);
                OIDCProviderMetadata m = new OIDCProviderMetadata(
                        new Issuer(config.issuerUrl),
                        List.of(SubjectType.PUBLIC),
                        jwksUri);
                m.setAuthorizationEndpointURI(authUri);
                m.setTokenEndpointURI(tokenUri);
                this.metadata = m;
                this.jwkSource = new RemoteJWKSet<>(jwksUri.toURL());
            } catch (Exception e) {
                throw new IOException("Provider '" + config.id + "': invalid endpoint override URI", e);
            }
        } else {
            // Automatic mode: resolve from .well-known/openid-configuration
            try {
                this.metadata = OIDCProviderMetadata.resolve(new Issuer(config.issuerUrl));
                this.jwkSource = new RemoteJWKSet<>(metadata.getJWKSetURI().toURL());
            } catch (Exception e) {
                throw new IOException("Failed to resolve OIDC provider metadata for issuer: " + config.issuerUrl, e);
            }
        }
    }

    /** Package-private constructor for unit tests — accepts pre-built metadata and JWK source. */
    OidcAuthHandler(OidcProviderConfig config, OIDCProviderMetadata metadata, JWKSource<SecurityContext> jwkSource) {
        this.config = config;
        this.metadata = metadata;
        this.jwkSource = jwkSource;
    }

    String getProviderId() {
        return config.id;
    }

    /**
     * Builds the authorization URI to redirect the browser to the OIDC provider.
     */
    URI buildAuthorizationUri(String encryptedState, String redirectUri) {
        List<String> scopeValues = new ArrayList<>();
        scopeValues.add("openid");
        scopeValues.add("email");
        scopeValues.addAll(config.additionalScopes);

        AuthenticationRequest request = new AuthenticationRequest.Builder(
                new ResponseType(ResponseType.Value.CODE),
                new Scope(scopeValues.toArray(new String[0])),
                new ClientID(config.clientId),
                URI.create(redirectUri))
                .endpointURI(metadata.getAuthorizationEndpointURI())
                .state(new State(encryptedState))
                .build();
        return request.toURI();
    }

    /**
     * Exchanges the authorization code for tokens at the provider's token endpoint.
     *
     * @return the OIDC tokens, or {@code null} on failure (error is logged)
     */
    OIDCTokens exchangeCode(String code, String redirectUri) throws IOException {
        try {
            TokenRequest tokenRequest = new TokenRequest(
                    metadata.getTokenEndpointURI(),
                    new ClientSecretBasic(new ClientID(config.clientId), new Secret(config.clientSecret)),
                    new AuthorizationCodeGrant(new AuthorizationCode(code), URI.create(redirectUri)));

            TokenResponse tokenResponse = OIDCTokenResponseParser.parse(tokenRequest.toHTTPRequest().send());
            if (!tokenResponse.indicatesSuccess()) {
                TokenErrorResponse errorResponse = tokenResponse.toErrorResponse();
                log.warning("Token endpoint returned error: " + errorResponse.getErrorObject());
                return null;
            }
            return ((OIDCTokenResponse) tokenResponse.toSuccessResponse()).getOIDCTokens();
        } catch (Exception e) {
            throw new IOException("Failed to exchange authorization code", e);
        }
    }

    /**
     * Validates the ID token's signature and all required claims.
     *
     * @param idToken the ID token JWT received from the token endpoint
     * @return the user's email address on success; {@code null} on any validation failure
     */
    String validateIdToken(JWT idToken) {
        try {
            ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();

            // Accept RS256 and ES256; alg=none is rejected by Nimbus
            JWSVerificationKeySelector<SecurityContext> keySelector = new JWSVerificationKeySelector<>(
                    Set.of(JWSAlgorithm.RS256, JWSAlgorithm.ES256),
                    jwkSource);
            jwtProcessor.setJWSKeySelector(keySelector);

            JWTClaimsSet claims = jwtProcessor.process(idToken, null);

            // Validate issuer
            if (!config.issuerUrl.equals(claims.getIssuer())) {
                log.warning("OIDC id_token issuer mismatch: expected=" + config.issuerUrl
                        + " got=" + claims.getIssuer());
                return null;
            }

            // Validate audience
            if (!claims.getAudience().contains(config.clientId)) {
                log.warning("OIDC id_token audience does not contain client_id");
                return null;
            }

            // Extract email from configured claim
            String email = claims.getStringClaim(config.emailClaim);
            if (email == null || email.isEmpty()) {
                log.warning("OIDC id_token does not contain claim: " + config.emailClaim);
                return null;
            }
            return email;

        } catch (Exception e) {
            log.warning("OIDC id_token validation failed", e);
            return null;
        }
    }
}
