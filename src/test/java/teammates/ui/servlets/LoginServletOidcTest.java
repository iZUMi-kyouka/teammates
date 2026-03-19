package teammates.ui.servlets;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

import java.net.URI;

import jakarta.servlet.http.HttpSession;

import org.apache.http.HttpStatus;
import org.mockito.MockedStatic;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import teammates.common.util.Config;
import teammates.test.BaseTestCase;
import teammates.test.MockHttpServletRequest;
import teammates.test.MockHttpServletResponse;

/**
 * SUT: {@link LoginServlet} — OIDC-specific paths.
 */
public class LoginServletOidcTest extends BaseTestCase {

    private MockedStatic<Config> mockConfig;
    private MockedStatic<OidcProviderRegistry> mockOidcRegistry;

    @BeforeMethod
    public void setup() {
        mockOidcRegistry = mockStatic(OidcProviderRegistry.class);
        mockConfig = mockStatic(Config.class);
        mockConfig.when(Config::isDevServerLoginEnabled).thenReturn(false);
        mockConfig.when(Config::isUsingFirebase).thenReturn(false);
        mockConfig.when(Config::isUsingOidc).thenReturn(true);
    }

    @AfterMethod
    public void teardown() {
        mockConfig.close();
        mockOidcRegistry.close();
    }

    @Test
    public void testDoGet_unknownOidcProvider_returns400() throws Exception {
        mockOidcRegistry.when(() -> OidcProviderRegistry.getHandler(anyString())).thenReturn(null);
        mockOidcRegistry.when(() -> OidcProviderRegistry.getHandler(null)).thenReturn(null);

        LoginServlet servlet = new LoginServlet();

        MockHttpServletRequest req = new MockHttpServletRequest("GET",
                "https://teammates.example.com/login");
        req.addParam("provider", "unknown");
        MockHttpServletResponse resp = new MockHttpServletResponse();

        servlet.doGet(req, resp);

        assertEquals(HttpStatus.SC_BAD_REQUEST, resp.getStatus());
    }

    @Test
    public void testDoGet_oidcEnabled_redirectsToProviderWithCorrectParams() throws Exception {
        OidcAuthHandler handler = mock(OidcAuthHandler.class);
        when(handler.getProviderId()).thenReturn("default");
        when(handler.buildAuthorizationUri(anyString(), anyString()))
                .thenReturn(URI.create("https://provider.example.com/authorize?response_type=code"));

        mockOidcRegistry.when(() -> OidcProviderRegistry.getHandler(null)).thenReturn(handler);
        mockOidcRegistry.when(() -> OidcProviderRegistry.getHandler("default")).thenReturn(handler);

        HttpSession session = mock(HttpSession.class);
        when(session.getId()).thenReturn("session-abc");

        LoginServlet servlet = new LoginServlet();

        MockHttpServletRequest req = new MockHttpServletRequest("GET",
                "https://teammates.example.com/login") {
            @Override
            public HttpSession getSession() {
                return session;
            }

            @Override
            public HttpSession getSession(boolean create) {
                return session;
            }
        };
        MockHttpServletResponse resp = new MockHttpServletResponse();

        servlet.doGet(req, resp);

        // Verify redirect to provider URL
        assertNotNull(resp.getRedirectUrl());
        assertTrue(resp.getRedirectUrl().startsWith("https://provider.example.com/authorize"));
    }

    @Test
    public void testDoGet_validCookiePresent_skipOidc() throws Exception {
        // When the user already has a valid auth cookie, LoginServlet skips OIDC entirely
        LoginServlet servlet = new LoginServlet();

        // Build a valid auth cookie value
        teammates.common.datatransfer.UserInfoCookie uic =
                new teammates.common.datatransfer.UserInfoCookie("already@logged.in");
        String cookieValue = teammates.common.util.StringHelper.encrypt(
                teammates.common.util.JsonUtils.toCompactJson(uic));

        MockHttpServletRequest req = new MockHttpServletRequest("GET",
                "https://teammates.example.com/login");
        req.addParam("nextUrl", "/web/instructor/home");
        req.addCookie(new jakarta.servlet.http.Cookie(
                teammates.common.util.Const.SecurityConfig.AUTH_COOKIE_NAME, cookieValue));
        MockHttpServletResponse resp = new MockHttpServletResponse();

        servlet.doGet(req, resp);

        // OIDC registry should never be consulted
        mockOidcRegistry.verifyNoInteractions();
    }
}
