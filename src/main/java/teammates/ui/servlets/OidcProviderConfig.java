package teammates.ui.servlets;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Properties;

/**
 * Immutable value class holding the configuration for a single OIDC provider.
 *
 * <p>Values are read from build.properties using the prefix {@code app.oidc.{id}.}.
 */
final class OidcProviderConfig {

    final String id;
    final String issuerUrl;
    final String clientId;
    final String clientSecret;
    final String emailClaim;
    final List<String> additionalScopes;
    final String authorizationEndpointOverride; // app.oidc.{id}.override.authorization.endpoint
    final String tokenEndpointOverride;          // app.oidc.{id}.override.token.endpoint
    final String jwksEndpointOverride;           // app.oidc.{id}.override.jwks.endpoint

    private OidcProviderConfig(String id, String issuerUrl, String clientId, String clientSecret,
            String emailClaim, List<String> additionalScopes,
            String authorizationEndpointOverride, String tokenEndpointOverride, String jwksEndpointOverride) {
        this.id = id;
        this.issuerUrl = issuerUrl;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.emailClaim = emailClaim;
        this.additionalScopes = Collections.unmodifiableList(additionalScopes);
        this.authorizationEndpointOverride = authorizationEndpointOverride;
        this.tokenEndpointOverride = tokenEndpointOverride;
        this.jwksEndpointOverride = jwksEndpointOverride;
    }

    /**
     * Reads the configuration for provider {@code id} from the supplied {@link Properties}.
     *
     * <p>The properties are expected to follow the naming convention:
     * {@code app.oidc.{id}.issuer.url}, {@code app.oidc.{id}.client.id}, etc.
     */
    static OidcProviderConfig fromProperties(Properties props, String id) {
        String prefix = "app.oidc." + id + ".";
        String issuerUrl = props.getProperty(prefix + "issuer.url", "");
        String clientId = props.getProperty(prefix + "client.id", "");
        String clientSecret = props.getProperty(prefix + "client.secret", "");
        String emailClaim = props.getProperty(prefix + "email.claim", "email");
        String additionalScopesRaw = props.getProperty(prefix + "additional.scopes", "");
        List<String> additionalScopes = additionalScopesRaw.isEmpty()
                ? Collections.emptyList()
                : Arrays.asList(additionalScopesRaw.split(","));
        String authOverride = props.getProperty(prefix + "override.authorization.endpoint", null);
        String tokenOverride = props.getProperty(prefix + "override.token.endpoint", null);
        String jwksOverride = props.getProperty(prefix + "override.jwks.endpoint", null);
        // treat empty string as absent
        if (authOverride != null && authOverride.isEmpty()) {
            authOverride = null;
        }
        if (tokenOverride != null && tokenOverride.isEmpty()) {
            tokenOverride = null;
        }
        if (jwksOverride != null && jwksOverride.isEmpty()) {
            jwksOverride = null;
        }
        return new OidcProviderConfig(id, issuerUrl, clientId, clientSecret,
                emailClaim, additionalScopes, authOverride, tokenOverride, jwksOverride);
    }
}
