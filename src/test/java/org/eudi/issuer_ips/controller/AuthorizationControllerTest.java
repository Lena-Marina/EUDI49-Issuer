package org.eudi.issuer_ips.controller;

import org.eudi.issuer_ips.config.IssuerProperties;
import org.eudi.issuer_ips.model.IssuedAuthorizationCode;
import org.eudi.issuer_ips.service.AuthenticationProvider;
import org.eudi.issuer_ips.service.AuthorizationCodeService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Interface test: The controller runs with a replacement implementation
 * of AuthenticationProvider, without any changes to the controller.
 * Pure JUnit test without a Spring context.
 */
class AuthorizationControllerTest {

    private static final String CLIENT_ID = "https://wallet.a-sit.at/app";
    private static final String REDIRECT_URI = "asitplus-wallet://wallet.a-sit.at/app/callback/provisioning";

    private static final Pattern REQUEST_ID = Pattern.compile("name=\"requestId\" value=\"([^\"]+)\"");
    private static final Pattern CODE = Pattern.compile("[?&]code=([^&]+)");

    /** replacement implementation, independent of the configuration */
    private static final AuthenticationProvider FAKE_PROVIDER = (username, password) ->
            "tester".equals(username) && "pw".equals(password) ? Optional.of("fake-user") : Optional.empty();

    private AuthorizationCodeService codeService;
    private AuthorizationController controller;

    @BeforeEach
    void setUp() {
        IssuerProperties properties = new IssuerProperties(
                new IssuerProperties.WalletClient(CLIENT_ID, REDIRECT_URI), Map.of(), Map.of());
        codeService = new AuthorizationCodeService();
        controller = new AuthorizationController(FAKE_PROVIDER, codeService, properties);
    }

    private ResponseEntity<String> get(String redirectUri) {
        return controller.showLoginForm("code", CLIENT_ID, redirectUri, "abc", "xyz", "S256",
                "[{\"type\":\"openid_credential\",\"credential_configuration_id\":\"urn:eu.europa.ec.eudi:ips:1\"}]");
    }

    private static String extract(Pattern pattern, String text) {
        Matcher m = pattern.matcher(text);
        assertTrue(m.find(), "Muster nicht gefunden in: " + text);
        return URLDecoder.decode(m.group(1), StandardCharsets.UTF_8);
    }

    @Test
    void validRequestShowsLoginForm() {
        ResponseEntity<String> response = get(REDIRECT_URI);
        assertEquals(200, response.getStatusCode().value());
        assertNotNull(extract(REQUEST_ID, response.getBody()));
    }

    @Test
    void wrongRedirectUriGives400WithoutRedirect() {
        ResponseEntity<String> response = get("https://evil.example/callback");
        assertEquals(400, response.getStatusCode().value());
        assertNull(response.getHeaders().getFirst(HttpHeaders.LOCATION));
    }

    @Test
    void wrongCodeChallengeMethodGives400() {
        ResponseEntity<String> response =
                controller.showLoginForm("code", CLIENT_ID, REDIRECT_URI, "abc", "xyz", "plain", null);
        assertEquals(400, response.getStatusCode().value());
    }

    @Test
    void wrongPasswordGives401WithoutCodeAndAllowsRetry() {
        String requestId = extract(REQUEST_ID, get(REDIRECT_URI).getBody());

        ResponseEntity<String> failed = controller.login(requestId, "tester", "falsch");
        assertEquals(401, failed.getStatusCode().value());
        assertNull(failed.getHeaders().getFirst(HttpHeaders.LOCATION));
        assertFalse(failed.getBody().contains("code="));

        // retry with the same requestId works (the request is not consumed on failed login)
        ResponseEntity<String> retry = controller.login(requestId, "tester", "pw");
        assertEquals(302, retry.getStatusCode().value());
    }

    @Test
    void correctPasswordRedirectsWithCodeBoundToUserId() {
        String requestId = extract(REQUEST_ID, get(REDIRECT_URI).getBody());

        ResponseEntity<String> response = controller.login(requestId, "tester", "pw");
        assertEquals(302, response.getStatusCode().value());

        String location = response.getHeaders().getFirst(HttpHeaders.LOCATION);
        assertNotNull(location);
        assertTrue(location.startsWith(REDIRECT_URI + "?code="), location);
        assertTrue(location.endsWith("&state=abc"), location);

        String code = extract(CODE, location);
        Optional<IssuedAuthorizationCode> issued = codeService.redeemCode(code);
        assertTrue(issued.isPresent());
        assertEquals("fake-user", issued.get().userId());
        assertEquals("xyz", issued.get().codeChallenge());

        // Code can be used exactly once
        assertTrue(codeService.redeemCode(code).isEmpty());
    }

    @Test
    void requestIdCannotBeUsedTwice() {
        String requestId = extract(REQUEST_ID, get(REDIRECT_URI).getBody());
        assertEquals(302, controller.login(requestId, "tester", "pw").getStatusCode().value());
        assertEquals(400, controller.login(requestId, "tester", "pw").getStatusCode().value());
    }

    @Test
    void unknownRequestIdGives400() {
        assertEquals(400, controller.login("gibt-es-nicht", "tester", "pw").getStatusCode().value());
        assertEquals(400, controller.login(null, "tester", "pw").getStatusCode().value());
    }
}