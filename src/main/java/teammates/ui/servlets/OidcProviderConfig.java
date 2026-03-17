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

    private OidcProviderConfig(String id, String issuerUrl, String clientId, String clientSecret,
            String emailClaim, List<String> additionalScopes) {
        this.id = id;
        this.issuerUrl = issuerUrl;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.emailClaim = emailClaim;
        this.additionalScopes = Collections.unmodifiableList(additionalScopes);
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
        return new OidcProviderConfig(id, issuerUrl, clientId, clientSecret,
                emailClaim, additionalScopes);
    }
}
