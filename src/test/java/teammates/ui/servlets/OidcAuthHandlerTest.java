package teammates.ui.servlets;

import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.List;
import java.util.Properties;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;

import teammates.test.BaseTestCase;

/**
 * SUT: {@link OidcAuthHandler#validateIdToken(com.nimbusds.jwt.JWT)}.
 */
public class OidcAuthHandlerTest extends BaseTestCase {

    private static final String ISSUER = "https://issuer.example.com";
    private static final String CLIENT_ID = "test-client";

    private RSAKey rsaJwk;
    private OidcAuthHandler handler;

    @BeforeClass
    public void classSetup() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        rsaJwk = new RSAKey.Builder(
                (java.security.interfaces.RSAPublicKey) kp.getPublic())
                .privateKey((java.security.interfaces.RSAPrivateKey) kp.getPrivate())
                .keyID("test-key-id")
                .build();

        JWKSet jwkSet = new JWKSet(rsaJwk.toPublicJWK());
        JWKSource<SecurityContext> jwkSource = new ImmutableJWKSet<>(jwkSet);

        Properties props = new Properties();
        props.setProperty("app.oidc.default.issuer.url", ISSUER);
        props.setProperty("app.oidc.default.client.id", CLIENT_ID);
        props.setProperty("app.oidc.default.client.secret", "secret");
        props.setProperty("app.oidc.default.email.claim", "email");
        OidcProviderConfig config = OidcProviderConfig.fromProperties(props, "default");

        OIDCProviderMetadata metadata = new OIDCProviderMetadata(
                new com.nimbusds.oauth2.sdk.id.Issuer(ISSUER),
                List.of(com.nimbusds.openid.connect.sdk.SubjectType.PUBLIC),
                URI.create(ISSUER + "/.well-known/jwks.json"));
        metadata.setAuthorizationEndpointURI(URI.create(ISSUER + "/authorize"));
        metadata.setTokenEndpointURI(URI.create(ISSUER + "/token"));

        handler = new OidcAuthHandler(config, metadata, jwkSource);
    }

    private SignedJWT buildIdToken(String issuer, List<String> audience, String email,
            long expirationEpochMillis, String emailClaim) throws Exception {
        JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .audience(audience)
                .subject("user-123")
                .expirationTime(new java.util.Date(expirationEpochMillis)); //NOPMD - Nimbus JWT API requires java.util.Date
        if (emailClaim != null) {
            claims.claim(emailClaim, email);
        }
        SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("test-key-id").build(),
                claims.build());
        jwt.sign(new RSASSASigner(rsaJwk));
        return jwt;
    }

    @Test
    public void testValidateIdToken_validToken_returnsEmail() throws Exception {
        long exp = System.currentTimeMillis() + 60_000;
        SignedJWT jwt = buildIdToken(ISSUER, List.of(CLIENT_ID), "user@example.com", exp, "email");
        String email = handler.validateIdToken(jwt);
        assertEquals("user@example.com", email);
    }

    @Test
    public void testValidateIdToken_issuerMismatch_returnsNull() throws Exception {
        long exp = System.currentTimeMillis() + 60_000;
        SignedJWT jwt = buildIdToken("https://evil.example.com", List.of(CLIENT_ID),
                "user@example.com", exp, "email");
        String email = handler.validateIdToken(jwt);
        assertNull(email);
    }

    @Test
    public void testValidateIdToken_audienceMismatch_returnsNull() throws Exception {
        long exp = System.currentTimeMillis() + 60_000;
        SignedJWT jwt = buildIdToken(ISSUER, List.of("other-client"), "user@example.com", exp, "email");
        String email = handler.validateIdToken(jwt);
        assertNull(email);
    }

    @Test
    public void testValidateIdToken_expiredToken_returnsNull() throws Exception {
        long exp = System.currentTimeMillis() - 60_000;
        SignedJWT jwt = buildIdToken(ISSUER, List.of(CLIENT_ID), "user@example.com", exp, "email");
        String email = handler.validateIdToken(jwt);
        assertNull(email);
    }

    @Test
    public void testValidateIdToken_nonDefaultEmailClaim_returnsCorrectEmail() throws Exception {
        Properties props = new Properties();
        props.setProperty("app.oidc.alt.issuer.url", ISSUER);
        props.setProperty("app.oidc.alt.client.id", CLIENT_ID);
        props.setProperty("app.oidc.alt.client.secret", "secret");
        props.setProperty("app.oidc.alt.email.claim", "preferred_username");
        OidcProviderConfig altConfig = OidcProviderConfig.fromProperties(props, "alt");

        JWKSet jwkSet = new JWKSet(rsaJwk.toPublicJWK());
        JWKSource<SecurityContext> jwkSource = new ImmutableJWKSet<>(jwkSet);

        OIDCProviderMetadata metadata = new OIDCProviderMetadata(
                new com.nimbusds.oauth2.sdk.id.Issuer(ISSUER),
                List.of(com.nimbusds.openid.connect.sdk.SubjectType.PUBLIC),
                URI.create(ISSUER + "/.well-known/jwks.json"));
        metadata.setAuthorizationEndpointURI(URI.create(ISSUER + "/authorize"));
        metadata.setTokenEndpointURI(URI.create(ISSUER + "/token"));

        OidcAuthHandler altHandler = new OidcAuthHandler(altConfig, metadata, jwkSource);

        long exp = System.currentTimeMillis() + 60_000;
        SignedJWT jwt = buildIdToken(ISSUER, List.of(CLIENT_ID),
                "entra-user@corp.com", exp, "preferred_username");

        String email = altHandler.validateIdToken(jwt);
        assertEquals("entra-user@corp.com", email);
    }
}
