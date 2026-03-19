package teammates.ui.servlets;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

import jakarta.servlet.http.HttpSession;

import org.apache.http.HttpStatus;
import org.mockito.MockedStatic;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.nimbusds.jwt.JWT;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;

import teammates.common.util.Config;
import teammates.common.util.JsonUtils;
import teammates.common.util.StringHelper;
import teammates.test.BaseTestCase;
import teammates.test.MockHttpServletRequest;
import teammates.test.MockHttpServletResponse;

/**
 * SUT: {@link OAuth2CallbackServlet} — OIDC-specific paths.
 */
public class OAuth2CallbackServletOidcTest extends BaseTestCase {

    private static final String SESSION_ID = "session-oidc-test";

    private MockedStatic<Config> mockConfig;
    private MockedStatic<OidcProviderRegistry> mockOidcRegistry;

    @BeforeMethod
    public void setup() {
        mockOidcRegistry = mockStatic(OidcProviderRegistry.class);
        mockConfig = mockStatic(Config.class);
        mockConfig.when(Config::isUsingFirebase).thenReturn(false);
        mockConfig.when(Config::isUsingOidc).thenReturn(true);
    }

    @AfterMethod
    public void teardown() {
        mockConfig.close();
        mockOidcRegistry.close();
    }

    private MockHttpServletRequest buildCallbackRequest(String code, String state, String error,
            HttpSession session) {
        MockHttpServletRequest req = new MockHttpServletRequest("GET",
                "https://teammates.example.com/oauth2callback") {
            @Override
            public HttpSession getSession() {
                return session;
            }

            @Override
            public HttpSession getSession(boolean create) {
                return session;
            }
        };
        if (code != null) {
            req.addParam("code", code);
        }
        if (state != null) {
            req.addParam("state", state);
        }
        if (error != null) {
            req.addParam("error", error);
        }
        return req;
    }

    private HttpSession buildSession(String sessionId) {
        HttpSession session = mock(HttpSession.class);
        when(session.getId()).thenReturn(sessionId);
        return session;
    }

    private String buildEncryptedState(String nextUrl, String sessionId, String providerId) {
        AuthServlet.AuthState state = new AuthServlet.AuthState(nextUrl, sessionId, providerId);
        return StringHelper.encrypt(JsonUtils.toCompactJson(state));
    }

    @Test
    public void testGetOidcAuthResult_errorParam_returns500() throws Exception {
        HttpSession session = buildSession(SESSION_ID);
        MockHttpServletRequest req = buildCallbackRequest(null, null, "access_denied", session);
        MockHttpServletResponse resp = new MockHttpServletResponse();

        new OAuth2CallbackServlet().doGet(req, resp);

        assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, resp.getStatus());
    }

    @Test
    public void testGetOidcAuthResult_errorParam_doesNotReflectUserInput() throws Exception {
        HttpSession session = buildSession(SESSION_ID);
        String xssPayload = "<script>alert(document.cookie)</script>";
        MockHttpServletRequest req = buildCallbackRequest(null, null, xssPayload, session);
        MockHttpServletResponse resp = new MockHttpServletResponse();

        new OAuth2CallbackServlet().doGet(req, resp);

        assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, resp.getStatus());
        assertFalse("Response body must not reflect the raw error parameter", resp.getBody().contains(xssPayload));
    }

    @Test
    public void testGetOidcAuthResult_missingCode_returns400() throws Exception {
        HttpSession session = buildSession(SESSION_ID);
        // state present but code missing
        String state = buildEncryptedState("/", SESSION_ID, "default");
        MockHttpServletRequest req = buildCallbackRequest(null, state, null, session);
        MockHttpServletResponse resp = new MockHttpServletResponse();

        new OAuth2CallbackServlet().doGet(req, resp);

        assertEquals(HttpStatus.SC_BAD_REQUEST, resp.getStatus());
    }

    @Test
    public void testGetOidcAuthResult_sessionIdMismatch_returns400() throws Exception {
        // Session now reports a different ID than what was encoded in state
        HttpSession session = buildSession("different-session-id");
        String state = buildEncryptedState("/", SESSION_ID, "default");
        MockHttpServletRequest req = buildCallbackRequest("auth-code", state, null, session);
        MockHttpServletResponse resp = new MockHttpServletResponse();

        new OAuth2CallbackServlet().doGet(req, resp);

        assertEquals(HttpStatus.SC_BAD_REQUEST, resp.getStatus());
    }

    @Test
    public void testGetOidcAuthResult_unknownOidcProvider_returns400() throws Exception {
        mockOidcRegistry.when(() -> OidcProviderRegistry.getHandler("unknown")).thenReturn(null);

        HttpSession session = buildSession(SESSION_ID);
        String state = buildEncryptedState("/", SESSION_ID, "unknown");
        MockHttpServletRequest req = buildCallbackRequest("auth-code", state, null, session);
        MockHttpServletResponse resp = new MockHttpServletResponse();

        new OAuth2CallbackServlet().doGet(req, resp);

        assertEquals(HttpStatus.SC_BAD_REQUEST, resp.getStatus());
    }

    @Test
    public void testGetOidcAuthResult_validFlow_setsEmailCookie() throws Exception {
        JWT mockIdToken = mock(JWT.class);
        OIDCTokens tokens = mock(OIDCTokens.class);
        when(tokens.getIDToken()).thenReturn(mockIdToken);

        OidcAuthHandler handler = mock(OidcAuthHandler.class);
        when(handler.exchangeCode(anyString(), anyString())).thenReturn(tokens);
        when(handler.validateIdToken(mockIdToken)).thenReturn("user@example.com");

        mockOidcRegistry.when(() -> OidcProviderRegistry.getHandler("default")).thenReturn(handler);

        HttpSession session = buildSession(SESSION_ID);
        String state = buildEncryptedState("/dashboard", SESSION_ID, "default");
        MockHttpServletRequest req = buildCallbackRequest("auth-code", state, null, session);
        MockHttpServletResponse resp = new MockHttpServletResponse();

        new OAuth2CallbackServlet().doGet(req, resp);

        // Should redirect and set a non-empty auth cookie
        assertNotNull(resp.getRedirectUrl());
        assertTrue(resp.getCookies().stream()
                .anyMatch(c -> teammates.common.util.Const.SecurityConfig.AUTH_COOKIE_NAME.equals(c.getName())
                        && !c.getValue().isEmpty()));
    }

    @Test
    public void testGetOidcAuthResult_invalidToken_setsInvalidationCookie() throws Exception {
        JWT mockIdToken = mock(JWT.class);
        OIDCTokens tokens = mock(OIDCTokens.class);
        when(tokens.getIDToken()).thenReturn(mockIdToken);

        OidcAuthHandler handler = mock(OidcAuthHandler.class);
        when(handler.exchangeCode(anyString(), anyString())).thenReturn(tokens);
        // validateIdToken returns null (validation failure)
        when(handler.validateIdToken(mockIdToken)).thenReturn(null);

        mockOidcRegistry.when(() -> OidcProviderRegistry.getHandler("default")).thenReturn(handler);

        HttpSession session = buildSession(SESSION_ID);
        String state = buildEncryptedState("/", SESSION_ID, "default");
        MockHttpServletRequest req = buildCallbackRequest("auth-code", state, null, session);
        MockHttpServletResponse resp = new MockHttpServletResponse();

        new OAuth2CallbackServlet().doGet(req, resp);

        // Should redirect and set the invalidation (zero max-age) cookie
        assertNotNull(resp.getRedirectUrl());
        assertTrue(resp.getCookies().stream()
                .anyMatch(c -> teammates.common.util.Const.SecurityConfig.AUTH_COOKIE_NAME.equals(c.getName())
                        && c.getMaxAge() == 0));
    }
}
