package org.eudi.issuer_ips.service;

import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.eudi.issuer_ips.MutableClock;
import org.eudi.issuer_ips.ProofJwts;
import org.eudi.issuer_ips.config.CredentialProperties;
import org.eudi.issuer_ips.config.IssuerUrlProperties;
import org.eudi.issuer_ips.model.IpsCredentialType;
import org.eudi.issuer_ips.testdata.TestBundle;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.*;

/**
 * SD-JWT VC payload for all three test bundles, checked with Nimbus in Java:
 * vct, cnf.jwk (= holder key from the proof), iat/exp from the clock, trailing "~".
 *
 * What only VC-K can show (ValidatorSdJwt.verifySdJwt, cnf against the wallet key,
 * VC-K's time rules, scheme lookup) is checked in the harness/valeria with the files
 * written by SdJwtVcExporter.
 */
class SdJwtVcPayloadTest {

    static final String ISSUER = "http://issuer.test:8080";
    /** With milliseconds, to see that iat is truncated to whole seconds. */
    static final Instant NOW = Instant.parse("2026-11-16T10:00:00.750Z");

    private static final ECKey HOLDER = ProofJwts.newKey();
    private static final ObjectMapper JSON = new ObjectMapper();

    /** Base64url segments: issuer JWT, then disclosures, each followed by "~". */
    private static final Pattern SD_JWT_SERIALIZATION = Pattern.compile(
            "^[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+~([A-Za-z0-9_-]+~)*$");

    /** SD-JWT VC: these claims must not be selectively disclosable. */
    private static final Set<String> PLAIN_ONLY = Set.of("iss", "vct", "cnf", "iat", "exp", "nbf", "sub", "status");

    private static JwtService service(Duration validity) {
        return new JwtService(new SigningKeyProvider(), new IssuerUrlProperties(ISSUER),
                new MutableClock(NOW), new CredentialProperties(validity));
    }

    private static String sdJwt(TestBundle bundle, ECKey holder) throws Exception {
        return service(Duration.ofDays(30)).createSdJwt(bundle.json(), holder);
    }

    private static JWTClaimsSet payload(String sdJwt) throws Exception {
        return SignedJWT.parse(sdJwt.substring(0, sdJwt.indexOf('~'))).getJWTClaimsSet();
    }

    /** Disclosure strings between the first and the trailing "~". */
    private static List<String> disclosures(String sdJwt) {
        String middle = sdJwt.substring(sdJwt.indexOf('~') + 1, sdJwt.length() - 1);
        return middle.isEmpty() ? List.of() : List.of(middle.split("~", -1));
    }

    // ---- vct ------------------------------------------------------------------

    @ParameterizedTest
    @EnumSource(TestBundle.class)
    void vctIsTheIpsTypeAsPlainClaim(TestBundle bundle) throws Exception {
        assertEquals("urn:eu.europa.ec.eudi:ips:1", payload(sdJwt(bundle, HOLDER)).getStringClaim("vct"));
    }

    /** Metadata and SD-JWT use the same constant: Valera assigns the scheme via vct. */
    @Test
    void vctEqualsVctInTheMetadata() throws Exception {
        String metadataVct = new CredentialIdentifierService(new IssuerUrlProperties(ISSUER))
                .getIssuerMetadata().getSupportedCredentialConfigurations()
                .get("urn:eu.europa.ec.eudi:ips:1").getVct();
        assertEquals(IpsCredentialType.VCT, metadataVct);
        assertEquals(metadataVct, payload(sdJwt(TestBundle.P15, HOLDER)).getStringClaim("vct"));
    }

    // ---- cnf --------------------------------------------------------------------

    /** cnf = {"jwk": holder public key}, exactly the key from the proof, without d. */
    @ParameterizedTest
    @EnumSource(TestBundle.class)
    void cnfJwkIsTheHolderPublicKey(TestBundle bundle) throws Exception {
        Map<String, Object> cnf = payload(sdJwt(bundle, HOLDER)).getJSONObjectClaim("cnf");

        assertNotNull(cnf, "cnf fehlt");
        assertEquals(Set.of("jwk"), cnf.keySet());
        @SuppressWarnings("unchecked")
        Map<String, Object> jwk = (Map<String, Object>) cnf.get("jwk");
        assertEquals(HOLDER.toPublicJWK().toJSONObject(), jwk);
        assertFalse(jwk.containsKey("d"), "privater Schlüssel im cnf");
        assertEquals(HOLDER.toPublicJWK(), ECKey.parse(jwk));
    }

    /** Test endpoint /sdjwt has no holder key: then there is no cnf (not storable in Valera). */
    @Test
    void noCnfWithoutHolderKey() throws Exception {
        assertNull(payload(sdJwt(TestBundle.P15, null)).getClaim("cnf"));
    }

    // ---- iat / exp ----------------------------------------------------------------

    @Test
    void iatAndExpComeFromTheClockInWholeSeconds() throws Exception {
        JWTClaimsSet claims = payload(sdJwt(TestBundle.P15, HOLDER));
        Map<String, Object> raw = JSONObjectUtils.parse(
                new Base64URL(sdJwt(TestBundle.P15, HOLDER).split("\\.")[1]).decodeToString());

        assertEquals(NOW.getEpochSecond(), claims.getIssueTime().toInstant().getEpochSecond());
        assertEquals(NOW.getEpochSecond() + Duration.ofDays(30).toSeconds(),
                claims.getExpirationTime().toInstant().getEpochSecond());
        assertInstanceOf(Long.class, raw.get("iat"), "iat als ganze Zahl (NumericDate)");
        assertInstanceOf(Long.class, raw.get("exp"), "exp als ganze Zahl (NumericDate)");
        assertNull(claims.getNotBeforeTime(), "nbf wird nicht gesetzt");
    }

    @Test
    void validityComesFromCredentialProperties() throws Exception {
        JWTClaimsSet claims = payload(service(Duration.ofHours(1)).createSdJwt(TestBundle.P1560.json(), HOLDER));
        assertEquals(3600, claims.getExpirationTime().toInstant().getEpochSecond()
                - claims.getIssueTime().toInstant().getEpochSecond());
    }

    @Test
    void missingZeroOrNegativeValidityIsRejected() {
        assertThrows(IllegalStateException.class, () -> new CredentialProperties(null));
        assertThrows(IllegalStateException.class, () -> new CredentialProperties(Duration.ZERO));
        assertThrows(IllegalStateException.class, () -> new CredentialProperties(Duration.ofDays(-1)));
    }

    // ---- serialization with trailing "~" -------------------------------------------

    /**
     * <JWT>~<D1>~...~<Dn>~ : ends with "~", no empty segment, every disclosure digest
     * is in _sd and every _sd entry belongs to a disclosure.
     */
    @ParameterizedTest
    @EnumSource(TestBundle.class)
    void serializationEndsWithTildeAndDisclosuresMatchSd(TestBundle bundle) throws Exception {
        String sdJwt = sdJwt(bundle, HOLDER);

        assertTrue(sdJwt.endsWith("~"), "abschließendes ~ fehlt");
        assertFalse(sdJwt.endsWith("~~"), "leeres Segment am Ende");
        assertTrue(SD_JWT_SERIALIZATION.matcher(sdJwt).matches(), "Serialisierung entspricht nicht <JWT>~(<D>~)*");

        List<String> disclosures = disclosures(sdJwt);
        assertFalse(disclosures.isEmpty());
        assertEquals("sha-256", payload(sdJwt).getStringClaim("_sd_alg"));

        Set<String> digests = new HashSet<>();
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        for (String d : disclosures) {
            digests.add(Base64URL.encode(sha256.digest(d.getBytes(StandardCharsets.US_ASCII))).toString());
        }
        assertEquals(new HashSet<>(payload(sdJwt).getStringListClaim("_sd")), digests);
    }

    /** vct, cnf, iss, iat, exp (and sub, nbf, status) are never inside a disclosure. */
    @ParameterizedTest
    @EnumSource(TestBundle.class)
    void registeredClaimsAreNotSelectivelyDisclosable(TestBundle bundle) throws Exception {
        for (String d : disclosures(sdJwt(bundle, HOLDER))) {
            List<?> disclosure = JSON.readValue(new Base64URL(d).decodeToString(), List.class);
            assertEquals(3, disclosure.size(), "Disclosure [salt, name, value] erwartet");
            assertFalse(PLAIN_ONLY.contains((String) disclosure.get(1)),
                    "Claim " + disclosure.get(1) + " darf nicht offenlegbar sein");
        }
    }
}
