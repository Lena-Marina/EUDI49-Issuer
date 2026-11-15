package org.eudi.issuer_ips.service;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.SignedJWT;
import org.eudi.issuer_ips.config.IssuerUrlProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * US11, AK 1-3: ES256, jwk in the header, typ dc+sd-jwt, signature R||S, iss from property.
 * Pure JUnit, no Spring context.
 */
class JwtServiceEs256Test {

    static final String ISSUER = "http://issuer.test:8080";

    /** Minimal IPS-like bundle: enough for createSdJwt to build disclosures. */
    static final String BUNDLE = """
            {"resourceType":"Bundle","type":"document","entry":[
              {"fullUrl":"urn:uuid:1","resource":{"resourceType":"Patient","id":"p1"}},
              {"fullUrl":"urn:uuid:2","resource":{"resourceType":"AllergyIntolerance","id":"a1"}}
            ]}""";

    private SigningKeyProvider keyProvider;
    private JwtService jwtService;

    @BeforeEach
    void setUp() {
        keyProvider = new SigningKeyProvider();
        jwtService = new JwtService(keyProvider, new IssuerUrlProperties(ISSUER));
    }

    /** Issuer-signed JWT = part before the first "~". */
    private SignedJWT issuerJwt() throws Exception {
        String sdJwt = jwtService.createSdJwt(BUNDLE, null);
        return SignedJWT.parse(sdJwt.substring(0, sdJwt.indexOf('~')));
    }

    // ---- AK 1: header ------------------------------------------------------

    @Test
    void headerHasEs256TypAndPublicJwkOnly() throws Exception {
        JWSHeader header = issuerJwt().getHeader();

        assertEquals(JWSAlgorithm.ES256, header.getAlgorithm());
        assertEquals("dc+sd-jwt", header.getType().getType());
        assertNull(header.getKeyID(), "kein kid");
        assertNull(header.getX509CertChain(), "kein x5c");
        assertNull(header.getJWKURL(), "kein jku");
        assertNull(header.getX509CertURL(), "kein x5u");
        assertEquals(Set.of("alg", "typ", "jwk"), header.toJSONObject().keySet());

        ECKey jwk = header.getJWK().toECKey();
        assertEquals("EC", jwk.getKeyType().getValue());
        assertEquals(Curve.P_256, jwk.getCurve());
        assertNotNull(jwk.getX());
        assertNotNull(jwk.getY());
        assertFalse(jwk.isPrivate(), "kein d im Header");
        assertEquals(Set.of("kty", "crv", "x", "y"), jwk.toJSONObject().keySet());
    }

    @Test
    void sdJwtEndsWithDisclosuresSeparatedByTilde() throws Exception {
        String sdJwt = jwtService.createSdJwt(BUNDLE, null);
        // 2 resource types -> 2 disclosures (abschließendes "~" folgt erst mit US15)
        assertEquals(2, sdJwt.chars().filter(c -> c == '~').count());
    }

    // ---- AK 2: signature ---------------------------------------------------

    @Test
    void signatureIs64BytesRandS() throws Exception {
        assertEquals(64, issuerJwt().getSignature().decode().length);
    }

    @Test
    void signatureVerifiesWithHeaderJwk() throws Exception {
        SignedJWT jwt = issuerJwt();
        ECKey headerKey = jwt.getHeader().getJWK().toECKey();
        assertTrue(jwt.verify(new ECDSAVerifier(headerKey)));
    }

    @Test
    void modifiedPayloadDoesNotVerify() throws Exception {
        SignedJWT original = issuerJwt();
        Base64URL[] parts = original.getParsedParts();

        // change iss (the SD-JWT has no sub)
        String payload = parts[1].decodeToString().replace(ISSUER, "http://attacker.test:8080");
        assertNotEquals(parts[1].decodeToString(), payload, "Payload wurde nicht verändert");

        SignedJWT tampered = SignedJWT.parse(parts[0] + "."
                + Base64URL.encode(payload.getBytes(StandardCharsets.UTF_8)) + "." + parts[2]);
        ECKey headerKey = tampered.getHeader().getJWK().toECKey();
        assertFalse(tampered.verify(new ECDSAVerifier(headerKey)));
    }

    @Test
    void plainJwtEndpointIsAlsoEs256() throws Exception {
        SignedJWT jwt = SignedJWT.parse(jwtService.createJwt("p1", BUNDLE));
        assertEquals(JWSAlgorithm.ES256, jwt.getHeader().getAlgorithm());
        assertTrue(jwt.verify(new ECDSAVerifier(jwt.getHeader().getJWK().toECKey())));
    }

    // ---- AK 3: iss from property ------------------------------------------

    @Test
    void issComesFromIssuerBaseUrl() throws Exception {
        assertEquals(ISSUER, issuerJwt().getJWTClaimsSet().getIssuer());
    }

    @Test
    void trailingSlashInPropertyGivesSameIss() {
        assertEquals(ISSUER, new IssuerUrlProperties(ISSUER + "/").credentialIssuer());
    }

    // ---- Decision A: key is generated per start ---------------------------

    @Test
    void everyProviderHasItsOwnKey() {
        assertNotEquals(new SigningKeyProvider().thumbprint(), new SigningKeyProvider().thumbprint());
    }
}
