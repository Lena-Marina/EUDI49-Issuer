package org.eudi.issuer_ips.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.SignedJWT;
import org.eudi.issuer_ips.MutableClock;
import org.eudi.issuer_ips.ProofJwts;
import org.eudi.issuer_ips.config.IssuerUrlProperties;
import org.eudi.issuer_ips.model.CredentialResponse;
import org.eudi.issuer_ips.service.AccessTokenService;
import org.eudi.issuer_ips.service.JwtService;
import org.eudi.issuer_ips.service.Pkce;
import org.eudi.issuer_ips.testdata.FakeFhirServer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * POST /credential with the full Spring context (MockMvc), as VC-K 5.10.1 calls it.
 * The FHIR server is a local fake that serves the test files (no network):
 *   user-anna -> nhanes-110387 (application.properties)
 *   user-ben  -> 15            (overridden here, so two users give two different test files)
 *   user-ghost -> a patient the FHIR server does not know (404)
 *   user-down  -> FHIR server answers 503
 */
@SpringBootTest
@AutoConfigureMockMvc
class CredentialEndpointTest {

    private static final String IPS = "urn:eu.europa.ec.eudi:ips:1";
    private static final String CLIENT_ID = ProofJwts.WALLET_CLIENT_ID;
    private static final String REDIRECT_URI = "asitplus-wallet://wallet.a-sit.at/app/callback/provisioning";
    private static final String VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private static final Instant START = Instant.parse("2026-11-16T10:00:00Z");
    private static final ObjectMapper JSON = new ObjectMapper();

    private static final FakeFhirServer FHIR = FakeFhirServer.start();

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        registry.add("issuer.fhir.base-url", FHIR::baseUrl);
        registry.add("issuer.patient-mapping.user-ben", () -> "15");
        registry.add("issuer.patient-mapping.user-ghost", () -> "unknown-patient");
        registry.add("issuer.patient-mapping.user-down", () -> FakeFhirServer.DOWN_PATIENT);
    }

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
    @Autowired private AccessTokenService accessTokenService;
    @Autowired private IssuerUrlProperties issuerUrls;
    @MockitoSpyBean private JwtService jwtService;

    @BeforeEach
    void reset() {
        clock.set(START);
        FHIR.clear();
    }

    @AfterAll
    static void stopFhir() {
        FHIR.close();
    }

    // ---- helpers -----------------------------------------------------------

    private String bearer(String userId) {
        return "Bearer " + accessTokenService.issue(userId);
    }

    private String proof(ECKey holder) {
        return ProofJwts.proof(holder, issuerUrls.credentialIssuer(), clock.instant()).build();
    }

    private static String body(String identifier, String... proofs) {
        return JSONObjectUtils.toJSONString(Map.of(
                "credential_identifier", identifier,
                "proofs", Map.of("jwt", List.of(proofs))));
    }

    private MvcResult postCredential(String authorization, String contentType, String body) throws Exception {
        MockHttpServletRequestBuilder request = post("/credential");
        if (authorization != null) {
            request.header(HttpHeaders.AUTHORIZATION, authorization);
        }
        if (contentType != null) {
            request.header(HttpHeaders.CONTENT_TYPE, contentType);
        }
        if (body != null) {
            request.content(body);
        }
        return mockMvc.perform(request).andReturn();
    }

    private MvcResult postValid(String userId, ECKey holder) throws Exception {
        return postCredential(bearer(userId), MediaType.APPLICATION_JSON_VALUE, body(IPS, proof(holder)));
    }

    private static JsonNode json(MvcResult result) throws Exception {
        return JSON.readTree(result.getResponse().getContentAsString(StandardCharsets.UTF_8));
    }

    private static Set<String> fieldNames(JsonNode node) {
        Set<String> names = new TreeSet<>();
        node.fieldNames().forEachRemaining(names::add);
        return names;
    }

    /** Every error is JSON with exactly error and error_description. */
    private static void assertError(MvcResult result, int status, String error) throws Exception {
        assertEquals(status, result.getResponse().getStatus(), "HTTP-Status");
        assertTrue(MediaType.APPLICATION_JSON.isCompatibleWith(
                MediaType.parseMediaType(result.getResponse().getContentType())), "Fehler als JSON");
        JsonNode body = json(result);
        assertEquals(Set.of("error", "error_description"), fieldNames(body));
        assertEquals(error, body.get("error").asText());
        assertFalse(body.get("error_description").asText().isBlank());
        assertEquals("no-store", result.getResponse().getHeader(HttpHeaders.CACHE_CONTROL));
    }

    private static void assertUnauthorized(MvcResult result) throws Exception {
        assertError(result, 401, "invalid_token");
        assertEquals("Bearer error=\"invalid_token\"", result.getResponse().getHeader(HttpHeaders.WWW_AUTHENTICATE));
    }

    private static String credentialOf(MvcResult result) throws Exception {
        return json(result).get("credentials").get(0).get("credential").asText();
    }

    /** Decoded disclosures of an SD-JWT (everything after the issuer JWT). */
    private static String disclosuresOf(String sdJwt) {
        StringBuilder decoded = new StringBuilder();
        String[] parts = sdJwt.split("~");
        for (int i = 1; i < parts.length; i++) {
            decoded.append(new Base64URL(parts[i]).decodeToString()).append('\n');
        }
        return decoded.toString();
    }

    // ---- Request format --------------------------------------------------

    @Test
    void unknownCredentialIdentifierIsRejected() throws Exception {
        MvcResult result = postCredential(bearer("user-anna"), MediaType.APPLICATION_JSON_VALUE,
                body("urn:eu.europa.ec.eudi:pid:1", proof(ProofJwts.newKey())));
        assertError(result, 400, "unknown_credential_identifier");
        assertTrue(FHIR.summaryRequests().isEmpty());
    }

    /** The token response announced credential_identifiers, so credential_configuration_id is wrong here. */
    @Test
    void credentialConfigurationIdInsteadOfIdentifierIsInvalidRequest() throws Exception {
        String body = JSONObjectUtils.toJSONString(Map.of(
                "credential_configuration_id", IPS,
                "proofs", Map.of("jwt", List.of(proof(ProofJwts.newKey())))));
        assertError(postCredential(bearer("user-anna"), MediaType.APPLICATION_JSON_VALUE, body),
                400, "invalid_credential_request");
    }

    /** Also for application/jwt (encrypted request) the answer is JSON, not Spring's 415 page. */
    @ParameterizedTest
    @ValueSource(strings = {"application/jwt", "text/plain", "application/x-www-form-urlencoded"})
    void nonJsonContentTypeIsInvalidRequest(String contentType) throws Exception {
        MvcResult result = postCredential(bearer("user-anna"), contentType, body(IPS, proof(ProofJwts.newKey())));
        assertError(result, 400, "invalid_credential_request");
    }

    @Test
    void malformedJsonIsInvalidRequest() throws Exception {
        assertError(postCredential(bearer("user-anna"), MediaType.APPLICATION_JSON_VALUE, "{kein json"),
                400, "invalid_credential_request");
    }

    // ---- Access token -----------------------------------------------------

    @Test
    void missingTokenIs401() throws Exception {
        assertUnauthorized(postCredential(null, MediaType.APPLICATION_JSON_VALUE, body(IPS, proof(ProofJwts.newKey()))));
    }

    @Test
    void unknownTokenIs401() throws Exception {
        assertUnauthorized(postCredential("Bearer kein-gueltiger-token", MediaType.APPLICATION_JSON_VALUE,
                body(IPS, proof(ProofJwts.newKey()))));
    }

    @Test
    void expiredTokenIs401() throws Exception {
        String authorization = bearer("user-anna");
        clock.advance(AccessTokenService.ACCESS_TOKEN_TTL);
        assertUnauthorized(postCredential(authorization, MediaType.APPLICATION_JSON_VALUE,
                body(IPS, proof(ProofJwts.newKey()))));
    }

    /** A valid token with another scheme (e.g. DPoP) is not accepted. */
    @Test
    void otherAuthorizationSchemeIs401() throws Exception {
        String token = accessTokenService.issue("user-anna");
        assertUnauthorized(postCredential("DPoP " + token, MediaType.APPLICATION_JSON_VALUE,
                body(IPS, proof(ProofJwts.newKey()))));
    }

    // ---- Proof --------------------------------------------------------------

    @Test
    void proofSignedWithOtherKeyIsInvalidProof() throws Exception {
        String badProof = ProofJwts.proof(ProofJwts.newKey(), issuerUrls.credentialIssuer(), clock.instant())
                .signWith(ProofJwts.newKey()).build();
        MvcResult result = postCredential(bearer("user-anna"), MediaType.APPLICATION_JSON_VALUE, body(IPS, badProof));
        assertError(result, 400, "invalid_proof");
        assertTrue(FHIR.summaryRequests().isEmpty(), "bei ungültigem Proof kein FHIR-Aufruf");
    }

    /** Proof created at START, sent 5 min 1 s later (token is still valid for 10 min). */
    @Test
    void proofOlderThanFiveMinutesIsInvalidProof() throws Exception {
        String authorization = bearer("user-anna");
        String oldProof = proof(ProofJwts.newKey());
        clock.advance(Duration.ofMinutes(5).plusSeconds(1));
        assertError(postCredential(authorization, MediaType.APPLICATION_JSON_VALUE, body(IPS, oldProof)),
                400, "invalid_proof");
    }

    /** proofs missing, empty, with two proofs (no batch) or as old singular "proof". */
    @ParameterizedTest
    @ValueSource(strings = {"missing", "empty", "two", "singular"})
    void brokenProofsParameterIsInvalidProof(String variant) throws Exception {
        String p = proof(ProofJwts.newKey());
        String body = switch (variant) {
            case "missing" -> JSONObjectUtils.toJSONString(Map.of("credential_identifier", IPS));
            case "empty" -> body(IPS);
            case "two" -> body(IPS, p, proof(ProofJwts.newKey()));
            case "singular" -> JSONObjectUtils.toJSONString(Map.of(
                    "credential_identifier", IPS,
                    "proof", Map.of("proof_type", "jwt", "jwt", p)));
            default -> throw new IllegalArgumentException(variant);
        };
        assertError(postCredential(bearer("user-anna"), MediaType.APPLICATION_JSON_VALUE, body), 400, "invalid_proof");
    }

    /** The holder key from the proof header is handed to the SD-JWT creation (cnf.jwk). */
    @Test
    void holderKeyFromProofIsHandedToJwtService() throws Exception {
        ECKey holder = ProofJwts.newKey();
        assertEquals(200, postValid("user-anna", holder).getResponse().getStatus());

        ArgumentCaptor<ECKey> captor = ArgumentCaptor.forClass(ECKey.class);
        verify(jwtService).createSdJwt(anyString(), captor.capture());
        assertEquals(holder.toPublicJWK().toJSONObject(), captor.getValue().toJSONObject());
        assertFalse(captor.getValue().isPrivate());
    }

    // ---- User identifier -> patient ID ------------------------------------

    @Test
    void userWithoutPatientIsDeniedWithoutFhirCall() throws Exception {
        MvcResult result = postValid("user-without-patient", ProofJwts.newKey());
        assertError(result, 400, "credential_request_denied");
        assertTrue(FHIR.summaryRequests().isEmpty(), "FHIR-Server wurde trotzdem gefragt: " + FHIR.summaryRequests());
    }

    @Test
    void twoUsersGetTwoDifferentPatients() throws Exception {
        String anna = credentialOf(postValid("user-anna", ProofJwts.newKey()));
        String ben = credentialOf(postValid("user-ben", ProofJwts.newKey()));

        assertEquals(List.of("nhanes-110387", "15"), FHIR.summaryRequests());
        assertTrue(disclosuresOf(anna).contains("Whitfields"), "anna: Patient aus nhanes-110387 erwartet");
        assertTrue(disclosuresOf(ben).contains("Roster"), "ben: Patient aus HL7-Datei 15 erwartet");
        assertFalse(disclosuresOf(anna).contains("Roster"));
        assertFalse(disclosuresOf(ben).contains("Whitfields"));
    }

    // ---- Response format -------------------------------------------------

    /** Exactly {"credentials":[{"credential":"<SD-JWT>"}]}, application/json, credential is a string. */
    @Test
    void successResponseHasExactlyTheVckFormat() throws Exception {
        MvcResult result = postValid("user-anna", ProofJwts.newKey());

        assertEquals(200, result.getResponse().getStatus());
        // VC-K (Ktor) compares type/subtype only; application/jwt would trigger decryption
        assertTrue(MediaType.APPLICATION_JSON.equalsTypeAndSubtype(
                        MediaType.parseMediaType(result.getResponse().getContentType())),
                "Content-Type muss application/json sein, war " + result.getResponse().getContentType());
        assertEquals("no-store", result.getResponse().getHeader(HttpHeaders.CACHE_CONTROL));

        JsonNode body = json(result);
        assertEquals(Set.of("credentials"), fieldNames(body), "nur credentials, kein transaction_id");
        assertTrue(body.get("credentials").isArray());
        assertEquals(1, body.get("credentials").size());
        JsonNode entry = body.get("credentials").get(0);
        assertEquals(Set.of("credential"), fieldNames(entry));
        assertTrue(entry.get("credential").isTextual(), "credential muss ein String sein, kein Objekt");

        String sdJwt = entry.get("credential").asText();
        SignedJWT issuerJwt = SignedJWT.parse(sdJwt.substring(0, sdJwt.indexOf('~')));
        assertEquals("dc+sd-jwt", issuerJwt.getHeader().getType().getType());
        assertTrue(issuerJwt.verify(new ECDSAVerifier((ECKey) issuerJwt.getHeader().getJWK())));
        assertEquals(issuerUrls.credentialIssuer(), issuerJwt.getJWTClaimsSet().getIssuer());
    }

    // ---- FHIR errors as JSON -----------------------------------------------

    @Test
    void patientUnknownOnFhirServerIs502ServerError() throws Exception {
        assertError(postValid("user-ghost", ProofJwts.newKey()), 502, "server_error");
        assertEquals(List.of("unknown-patient"), FHIR.summaryRequests());
    }

    @Test
    void fhirServerFailureIs502ServerError() throws Exception {
        assertError(postValid("user-down", ProofJwts.newKey()), 502, "server_error");
    }

    // ---- Sub documented (omitted), nothing in the log ------------------------

    /** Neither user identifier nor patient ID in sub. */
    @Test
    void sdJwtHasNoSub() throws Exception {
        String sdJwt = credentialOf(postValid("user-anna", ProofJwts.newKey()));
        SignedJWT issuerJwt = SignedJWT.parse(sdJwt.substring(0, sdJwt.indexOf('~')));

        assertNull(issuerJwt.getJWTClaimsSet().getSubject(), "sub muss fehlen");
        String payload = issuerJwt.getPayload().toString();
        assertFalse(payload.contains("user-anna"), "Nutzerkennung im Payload");
        assertFalse(payload.contains("nhanes-110387"), "Patient-ID im Payload");
    }

    /** Spring logs response bodies on DEBUG via toString(): the SD-JWT must not appear. */
    @Test
    void credentialResponseToStringHidesTheCredential() {
        String text = CredentialResponse.single("eyJhbGciOiJFUzI1NiJ9.geheim~disclosure").toString();
        assertFalse(text.contains("geheim"));
        assertFalse(text.contains("disclosure"));
    }

    // ---- whole flow ---------------------------------------------------------------

    /** /authorize (login anna/geheim1) -> /token -> /credential, like Valera does it. */
    @Test
    void endToEndAuthorizeTokenCredential() throws Exception {
        String authDetails = "[{\"type\":\"openid_credential\",\"credential_configuration_id\":\"" + IPS + "\"}]";
        MvcResult form = mockMvc.perform(get("/authorize")
                        .param("response_type", "code")
                        .param("client_id", CLIENT_ID)
                        .param("redirect_uri", REDIRECT_URI)
                        .param("state", "state-e2e")
                        .param("code_challenge", Pkce.s256(VERIFIER))
                        .param("code_challenge_method", "S256")
                        .param("authorization_details", authDetails))
                .andReturn();
        String requestId = find("name=\"requestId\" value=\"([^\"]+)\"",
                form.getResponse().getContentAsString(StandardCharsets.UTF_8));

        MvcResult login = mockMvc.perform(post("/authorize")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .content("requestId=" + URLEncoder.encode(requestId, StandardCharsets.UTF_8)
                                + "&username=anna&password=geheim1"))
                .andReturn();
        assertEquals(302, login.getResponse().getStatus());
        String code = find("[?&]code=([^&]+)", login.getResponse().getHeader(HttpHeaders.LOCATION));

        MvcResult token = mockMvc.perform(post("/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "authorization_code")
                        .param("code", code)
                        .param("redirect_uri", REDIRECT_URI)
                        .param("client_id", CLIENT_ID)
                        .param("code_verifier", VERIFIER))
                .andReturn();
        assertEquals(200, token.getResponse().getStatus());
        JsonNode tokenJson = json(token);

        MvcResult credential = postCredential(
                tokenJson.get("token_type").asText() + " " + tokenJson.get("access_token").asText(),
                MediaType.APPLICATION_JSON_VALUE,
                body(tokenJson.get("authorization_details").get(0).get("credential_identifiers").get(0).asText(),
                        proof(ProofJwts.newKey())));

        assertEquals(200, credential.getResponse().getStatus());
        assertEquals(List.of("nhanes-110387"), FHIR.summaryRequests());
        assertTrue(disclosuresOf(credentialOf(credential)).contains("Whitfields"));
    }

    private static String find(String regex, String text) {
        Matcher m = Pattern.compile(regex).matcher(text);
        assertTrue(m.find(), "Muster nicht gefunden: " + regex + " in " + text);
        return URLDecoder.decode(m.group(1), StandardCharsets.UTF_8);
    }
}
