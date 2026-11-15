package org.eudi.issuer_ips.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.eudi.issuer_ips.MutableClock;
import org.eudi.issuer_ips.service.AccessTokenService;
import org.eudi.issuer_ips.service.AuthorizationCodeService;
import org.eudi.issuer_ips.service.Pkce;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * POST /token with the full Spring context (MockMvc), as VC-K 5.10.1 calls it.
 * One test (or group) per acceptance criterion.
 */
@SpringBootTest
@AutoConfigureMockMvc
class TokenEndpointTest {

    private static final String CLIENT_ID = "https://wallet.a-sit.at/app";
    private static final String REDIRECT_URI = "asitplus-wallet://wallet.a-sit.at/app/callback/provisioning";
    private static final String VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"; // RFC 7636, App. B
    private static final String OTHER_VERIFIER = "ZZZftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private static final String REQUEST_AUTH_DETAILS =
            "[{\"type\":\"openid_credential\",\"credential_configuration_id\":\"urn:eu.europa.ec.eudi:ips:1\"}]";

    /** Eexactly this value, VC-K needs it to build the credential request. */
    private static final String EXPECTED_AUTH_DETAILS = """
            [{"type":"openid_credential",
              "credential_configuration_id":"urn:eu.europa.ec.eudi:ips:1",
              "credential_identifiers":["urn:eu.europa.ec.eudi:ips:1"]}]""";

    private static final Instant START = Instant.parse("2026-11-15T12:00:00Z");
    private static final ObjectMapper JSON = new ObjectMapper();

    @TestConfiguration
    static class TestClockConfig {
        @Bean
        @Primary
        MutableClock testClock() {
            return new MutableClock(START);
        }
    }

    @Autowired private MockMvc mockMvc;
    @Autowired private MutableClock clock;
    @Autowired private AuthorizationCodeService codeService;
    @Autowired private AccessTokenService accessTokenService;

    @BeforeEach
    void resetClock() {
        clock.set(START);
    }

    // ---- helpers -----------------------------------------------------------

    /** Code as /authorize would issue it for user-anna (logged in as anna). */
    private String newCode() {
        String requestId = codeService.createPendingRequest(
                CLIENT_ID, REDIRECT_URI, "state-1", Pkce.s256(VERIFIER), "S256", REQUEST_AUTH_DETAILS);
        return codeService.issueCode(requestId, "user-anna").orElseThrow();
    }

    private Map<String, String> validParams(String code) {
        Map<String, String> p = new LinkedHashMap<>();
        p.put("grant_type", "authorization_code");
        p.put("code", code);
        p.put("redirect_uri", REDIRECT_URI);
        p.put("client_id", CLIENT_ID);
        p.put("code_verifier", VERIFIER);
        p.put("authorization_details", REQUEST_AUTH_DETAILS);
        return p;
    }

    /** Sends the parameters as a real form body (like VC-K), not as query parameters. */
    private MvcResult postToken(Map<String, String> params) throws Exception {
        String body = params.entrySet().stream()
                .map(e -> URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8) + "="
                        + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8))
                .collect(Collectors.joining("&"));
        return mockMvc.perform(post("/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .content(body))
                .andReturn();
    }

    private static JsonNode json(MvcResult result) throws Exception {
        return JSON.readTree(result.getResponse().getContentAsString(StandardCharsets.UTF_8));
    }

    private static Set<String> keys(JsonNode node) {
        Set<String> keys = new TreeSet<>();
        node.fieldNames().forEachRemaining(keys::add);
        return keys;
    }

    /** Every error is JSON {"error", "error_description"} with HTTP 400 and no-store. */
    private static void assertError(MvcResult result, String expectedError) throws Exception {
        assertEquals(400, result.getResponse().getStatus());
        assertTrue(MediaType.APPLICATION_JSON.isCompatibleWith(
                MediaType.parseMediaType(result.getResponse().getContentType())));
        JsonNode body = json(result);
        assertEquals(Set.of("error", "error_description"), keys(body));
        assertEquals(expectedError, body.get("error").asText());
        assertFalse(body.get("error_description").asText().isBlank());
        assertEquals("no-store", result.getResponse().getHeader(HttpHeaders.CACHE_CONTROL));
    }

    // ---- Valid request gives token response --------------------------
    @Test
    void validFormRequestGivesTokenResponse() throws Exception {
        MvcResult result = postToken(validParams(newCode()));

        assertEquals(200, result.getResponse().getStatus());
        assertTrue(MediaType.APPLICATION_JSON.isCompatibleWith(
                MediaType.parseMediaType(result.getResponse().getContentType())));
        assertEquals("no-store", result.getResponse().getHeader(HttpHeaders.CACHE_CONTROL));

        JsonNode body = json(result);
        // exactly these fields: no scope, refresh_token, c_nonce
        assertEquals(Set.of("access_token", "token_type", "expires_in", "authorization_details"), keys(body));
        assertFalse(body.get("access_token").asText().isBlank());
        assertEquals("Bearer", body.get("token_type").asText());
        assertTrue(body.get("expires_in").isIntegralNumber(), "expires_in muss eine ganze Zahl sein");
        assertEquals(600, body.get("expires_in").asInt());
        assertEquals(JSON.readTree(EXPECTED_AUTH_DETAILS), body.get("authorization_details"));
    }

    @Test
    void requestWithoutAuthorizationDetailsStillGetsThem() throws Exception {
        Map<String, String> params = validParams(newCode());
        params.remove("authorization_details");
        MvcResult result = postToken(params);
        assertEquals(200, result.getResponse().getStatus());
        assertEquals(JSON.readTree(EXPECTED_AUTH_DETAILS), json(result).get("authorization_details"));
    }

    // ---- invalid_grant, code is used up after a failed attempt --------

    @Test
    void wrongCodeVerifierIsInvalidGrantAndConsumesCode() throws Exception {
        String code = newCode();
        Map<String, String> wrong = validParams(code);
        wrong.put("code_verifier", OTHER_VERIFIER);
        assertError(postToken(wrong), "invalid_grant");

        // correct verifier afterwards: code is already used up
        assertError(postToken(validParams(code)), "invalid_grant");
    }

    @Test
    void differentRedirectUriIsInvalidGrantAndConsumesCode() throws Exception {
        String code = newCode();
        Map<String, String> wrong = validParams(code);
        wrong.put("redirect_uri", "asitplus-wallet://wallet.a-sit.at/app/callback/other");
        assertError(postToken(wrong), "invalid_grant");
        assertError(postToken(validParams(code)), "invalid_grant");
    }

    @Test
    void differentClientIdIsInvalidGrantAndConsumesCode() throws Exception {
        String code = newCode();
        Map<String, String> wrong = validParams(code);
        wrong.put("client_id", "https://evil.example/app");
        assertError(postToken(wrong), "invalid_grant");
        assertError(postToken(validParams(code)), "invalid_grant");
    }

    @Test
    void unknownCodeIsInvalidGrant() throws Exception {
        assertError(postToken(validParams("gibt-es-nicht")), "invalid_grant");
    }

    @Test
    void codeCanBeRedeemedOnlyOnce() throws Exception {
        String code = newCode();
        assertEquals(200, postToken(validParams(code)).getResponse().getStatus());
        assertError(postToken(validParams(code)), "invalid_grant");
    }

    @Test
    void expiredCodeIsInvalidGrant() throws Exception {
        String code = newCode();
        clock.advance(AuthorizationCodeService.CODE_TTL);
        assertError(postToken(validParams(code)), "invalid_grant");
    }

    @Test
    void codeIsStillValidJustBeforeExpiry() throws Exception {
        String code = newCode();
        clock.advance(AuthorizationCodeService.CODE_TTL.minusSeconds(1));
        assertEquals(200, postToken(validParams(code)).getResponse().getStatus());
    }

    // ---- Unsupported_grant_type, invalid_request --------------------

    @Test
    void wrongGrantTypeIsUnsupportedGrantType() throws Exception {
        Map<String, String> params = validParams(newCode());
        params.put("grant_type", "refresh_token");
        assertError(postToken(params), "unsupported_grant_type");
    }

    @ParameterizedTest
    @ValueSource(strings = {"grant_type", "code", "redirect_uri", "client_id", "code_verifier"})
    void missingParameterIsInvalidRequest(String parameter) throws Exception {
        Map<String, String> params = validParams(newCode());
        params.remove(parameter);
        assertError(postToken(params), "invalid_request");
    }

    @Test
    void duplicateParameterIsInvalidRequest() throws Exception {
        String code = newCode();
        MvcResult result = mockMvc.perform(post("/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .content("grant_type=authorization_code&code=" + code + "&code=" + code
                                + "&redirect_uri=" + URLEncoder.encode(REDIRECT_URI, StandardCharsets.UTF_8)
                                + "&client_id=" + URLEncoder.encode(CLIENT_ID, StandardCharsets.UTF_8)
                                + "&code_verifier=" + VERIFIER))
                .andReturn();
        assertError(result, "invalid_request");
    }

    @Test
    void emptyBodyIsInvalidRequest() throws Exception {
        MvcResult result = mockMvc.perform(post("/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)).andReturn();
        assertError(result, "invalid_request");
    }

    // ---- Token bound to the user identifier, not to the patient ID ---

    @Test
    void accessTokenIsBoundToUserIdNotPatientId() throws Exception {
        String accessToken = json(postToken(validParams(newCode()))).get("access_token").asText();

        assertEquals(Optional.of("user-anna"), accessTokenService.resolveUserId(accessToken));
        assertNotEquals(Optional.of("nhanes-110387"), accessTokenService.resolveUserId(accessToken));
    }

    @Test
    void accessTokenExpiresAfterExpiresIn() throws Exception {
        String accessToken = json(postToken(validParams(newCode()))).get("access_token").asText();
        clock.advance(Duration.ofSeconds(600));
        assertTrue(accessTokenService.resolveUserId(accessToken).isEmpty());
    }

    // ---- Real login form -> code -> token ------------

    @Test
    void endToEndAuthorizeLoginToken() throws Exception {
        MvcResult form = mockMvc.perform(get("/authorize")
                        .param("response_type", "code")
                        .param("client_id", CLIENT_ID)
                        .param("redirect_uri", REDIRECT_URI)
                        .param("state", "state-e2e")
                        .param("code_challenge", Pkce.s256(VERIFIER))
                        .param("code_challenge_method", "S256")
                        .param("authorization_details", REQUEST_AUTH_DETAILS))
                .andReturn();
        assertEquals(200, form.getResponse().getStatus());
        String requestId = find("name=\"requestId\" value=\"([^\"]+)\"",
                form.getResponse().getContentAsString(StandardCharsets.UTF_8));

        MvcResult login = mockMvc.perform(post("/authorize")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .content("requestId=" + URLEncoder.encode(requestId, StandardCharsets.UTF_8)
                                + "&username=anna&password=geheim1"))
                .andReturn();
        assertEquals(302, login.getResponse().getStatus());
        String code = find("[?&]code=([^&]+)", login.getResponse().getHeader(HttpHeaders.LOCATION));

        MvcResult token = postToken(validParams(code));
        assertEquals(200, token.getResponse().getStatus());
        assertEquals(Optional.of("user-anna"),
                accessTokenService.resolveUserId(json(token).get("access_token").asText()));
    }

    private static String find(String regex, String text) {
        Matcher m = Pattern.compile(regex).matcher(text);
        assertTrue(m.find(), "Muster nicht gefunden: " + regex + " in " + text);
        return URLDecoder.decode(m.group(1), StandardCharsets.UTF_8);
    }
}
