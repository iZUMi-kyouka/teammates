package teammates.ui.servlets;

import java.io.IOException;
import java.io.InputStream;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;

import jakarta.servlet.ServletException;

import teammates.common.util.Config;
import teammates.common.util.FileHelper;
import teammates.common.util.Logger;

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

    private static final Logger log = Logger.getLogger();

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
        Properties properties = new Properties();
        try (InputStream buildPropStream = FileHelper.getResourceAsStream("build.properties")) {
            properties.load(buildPropStream);
        } catch (IOException e) {
            throw new ServletException("Failed to load build.properties for OIDC configuration", e);
        }

        // Also load dev overrides when available
        Properties devProperties = new Properties();
        if (Config.IS_DEV_SERVER) {
            try (InputStream devPropStream = FileHelper.getResourceAsStream("build-dev.properties")) {
                if (devPropStream != null) {
                    devProperties.load(devPropStream);
                }
            } catch (IOException e) {
                log.warning("Could not load build-dev.properties for OIDC configuration");
            }
        }

        // Merge: dev overrides take precedence
        Properties merged = new Properties(properties);
        merged.putAll(devProperties);

        String providerListRaw = merged.getProperty("app.oidc.providers", Config.OIDC_PROVIDERS);
        if (providerListRaw == null || providerListRaw.trim().isEmpty()) {
            throw new ServletException("app.auth.type=oidc but app.oidc.providers is not configured");
        }

        String[] ids = providerListRaw.split(",");
        Map<String, OidcAuthHandler> handlers = new LinkedHashMap<>();
        for (String rawId : ids) {
            String id = rawId.trim();
            if (id.isEmpty()) {
                continue;
            }
            OidcProviderConfig config = OidcProviderConfig.fromProperties(merged, id);
            try {
                handlers.put(id, new OidcAuthHandler(config));
            } catch (IOException e) {
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
