package teammates.ui.servlets;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;

import jakarta.servlet.ServletException;

import teammates.common.util.Config;

/**
 * Registry of configured OIDC providers.
 *
 * <p>Loaded once during servlet {@code init()} by reading {@link Config#OIDC_PROVIDERS} and
 * constructing an {@link OidcAuthHandler} for each named provider.
 *
 * <p>Providers are keyed by their ID string (e.g. {@code "default"}, {@code "google"},
 * {@code "okta"}).  When multiple providers are configured, the login URL includes a
 * {@code ?provider={id}} parameter; when only one provider is configured that parameter is
 * optional and the single provider is used as the default.
 */
final class OidcProviderRegistry {

    private static OidcProviderRegistry cachedInstance;

    private final Map<String, OidcAuthHandler> handlers;
    private final String defaultId;

    private OidcProviderRegistry(Map<String, OidcAuthHandler> handlers, String defaultId) {
        this.handlers = handlers;
        this.defaultId = defaultId;
    }

    /**
     * Builds the registry from the application properties files.
     *
     * @throws ServletException if no providers are configured or a provider fails to initialise
     */
    static OidcProviderRegistry load() throws ServletException {
        if (Config.OIDC_PROVIDERS == null || Config.OIDC_PROVIDERS.trim().isEmpty()) {
            throw new ServletException("app.auth.type=oidc but app.oidc.providers is not configured");
        }

        Properties oidcProperties = Config.getOidcProperties();
        String[] ids = Config.OIDC_PROVIDERS.split(",");
        Map<String, OidcAuthHandler> handlers = new LinkedHashMap<>();
        for (String rawId : ids) {
            String id = rawId.trim();
            if (id.isEmpty()) {
                continue;
            }
            try {
                OidcProviderConfig config = OidcProviderConfig.fromProperties(oidcProperties, id);
                handlers.put(id, new OidcAuthHandler(config));
            } catch (IOException | IllegalArgumentException e) {
                throw new ServletException("Failed to initialise OIDC handler for provider '" + id + "'", e);
            }
        }

        if (handlers.isEmpty()) {
            throw new ServletException("No valid OIDC providers found in app.oidc.providers");
        }

        String defaultId = handlers.keySet().iterator().next();
        return new OidcProviderRegistry(handlers, defaultId);
    }

    /**
     * Returns the shared registry instance, loading it on the first call.
     * Subsequent calls return the cached instance without repeating network I/O.
     *
     * <p>Safe to call without synchronization because servlet {@code init()} is
     * guaranteed to run in a single thread.
     */
    static OidcProviderRegistry getInstance() throws ServletException {
        if (cachedInstance == null) {
            cachedInstance = load();
        }
        return cachedInstance;
    }

    /**
     * Returns the handler for the given provider ID.
     *
     * <p>If {@code id} is {@code null} or blank, the default (first configured) provider is
     * returned.  Returns {@code null} when the given ID is non-blank but unknown.
     */
    OidcAuthHandler get(String id) {
        if (id == null || id.trim().isEmpty()) {
            return handlers.get(defaultId);
        }
        return handlers.get(id.trim());
    }
}
