package org.eudi.issuer_ips.service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.eudi.issuer_ips.config.CredentialProperties;
import org.eudi.issuer_ips.config.IssuerUrlProperties;
import org.eudi.issuer_ips.model.IpsCredentialType;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Creates JWT / SD-JWT from an IPS bundle.
 *
 * Signed with ES256 (key from SigningKeyProvider), public key as "jwk"
 * in the JWS header, iss = issuer.base-url (same value as credential_issuer).
 *
 * sub: the SD-JWT has NO sub claim. Neither the user identifier
 * nor the patient ID is put into the credential: sub cannot be disclosed selectively, so
 * every verifier would see a linkable identifier. Holder binding is done via cnf;
 * the person is described by the Patient resource inside the IPS. Fallback if VC-K/Valera
 * turns out to need sub: a random pseudonym per credential.
 *
 * SD-JWT VC payload, checked by Valera when storing (signature, vct, cnf):
 *   iss     = issuer.base-url
 *   vct     = IpsCredentialType.VCT (same constant as in the metadata)
 *   cnf     = {"jwk": holder public key from the proof}  (only if a holder key is given)
 *   iat/exp = whole seconds from the injected Clock; exp = iat + issuer.credential.validity
 *   _sd, _sd_alg = sha-256
 * vct, cnf, iss, iat, exp are plain claims, never disclosures (SD-JWT VC).
 * Serialization: <issuer JWT>~<disclosure 1>~...~<disclosure n>~ (trailing "~", no key binding JWT).
 *
 * No health data is written to the console or the log.
 */
@Service
public class JwtService {

    /** typ of an SD-JWT VC, as expected by VC-K 5.10.1. */
    static final JOSEObjectType SD_JWT_TYPE = new JOSEObjectType("dc+sd-jwt");

    /** Validity for the convenience constructor (unit tests); the application uses the property. */
    static final Duration DEFAULT_VALIDITY_FOR_TESTS = Duration.ofDays(30);

    private final SigningKeyProvider signingKeyProvider;
    private final IssuerUrlProperties issuerUrls;
    private final Clock clock;
    private final Duration validity;

    /** For unit tests without Spring: system clock, 30 days validity. */
    public JwtService(SigningKeyProvider signingKeyProvider, IssuerUrlProperties issuerUrls) {
        this(signingKeyProvider, issuerUrls, Clock.systemUTC(), new CredentialProperties(DEFAULT_VALIDITY_FOR_TESTS));
    }

    @Autowired
    public JwtService(SigningKeyProvider signingKeyProvider, IssuerUrlProperties issuerUrls,
                      Clock clock, CredentialProperties credentialProperties) {
        this.signingKeyProvider = signingKeyProvider;
        this.issuerUrls = issuerUrls;
        this.clock = clock;
        this.validity = credentialProperties.validity();
    }

    /** Simple JWT with the whole bundle (test endpoint /issuer/Patient/{id}/jwt only). */
    public String createJwt(String patientId, String fhirJson) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        Map<String, Object> fhirObject = mapper.readValue(fhirJson, new TypeReference<Map<String, Object>>() {});

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(issuerUrls.credentialIssuer())
                .subject(patientId)
                .issueTime(Date.from(clock.instant()))
                .expirationTime(Date.from(clock.instant().plusSeconds(3600)))
                .claim("fhir", fhirObject)
                .build();

        // plain JWT: no typ dc+sd-jwt, it is not an SD-JWT VC
        return sign(header(null), claims);
    }

    /**
     * SD-JWT for the IPS (used by /credential and by the test endpoint /issuer/Patient/{id}/sdjwt).
     *
     * @param fhirJson  IPS bundle as FHIR JSON
     * @param holderKey public key of the wallet from the proof (checked by ProofJwtValidator),
     *                  written to cnf.jwk; null only for the test endpoint /sdjwt (then no cnf,
     *                  and Valera would not store the credential)
     */
    public String createSdJwt(String fhirJson, ECKey holderKey) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        Map<String, Object> fhirObject = mapper.readValue(fhirJson, new TypeReference<>() {});

        // FHIR Bundle entries extrahieren
        List<Map<String, Object>> entries = (List<Map<String, Object>>) fhirObject.get("entry");

        // Claims nach resourceType gruppieren
        Map<String, List<Object>> claimsMap = new LinkedHashMap<>();
        if (entries != null) {
            for (Map<String, Object> entry : entries) {
                Map<String, Object> resource = (Map<String, Object>) entry.get("resource");
                if (resource == null) continue;
                String resourceType = (String) resource.get("resourceType");

                // z.B. "AllergyIntolerance" → "allergies"
                String claimName = mapResourceTypeToClaim(resourceType);
                claimsMap.computeIfAbsent(claimName, k -> new ArrayList<>()).add(resource);
            }
        }

        // Pro Claim eine Disclosure erstellen
        List<String> disclosures = new ArrayList<>();
        List<String> sdHashes = new ArrayList<>();

        for (Map.Entry<String, List<Object>> claim : claimsMap.entrySet()) {
            String salt = UUID.randomUUID().toString();
            List<Object> disclosureArray = List.of(salt, claim.getKey(), claim.getValue());

            String disclosureJson = mapper.writeValueAsString(disclosureArray);
            String disclosure = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(disclosureJson.getBytes(StandardCharsets.UTF_8));

            byte[] hashBytes = MessageDigest.getInstance("SHA-256")
                    .digest(disclosure.getBytes(StandardCharsets.US_ASCII));
            String hash = Base64.getUrlEncoder().withoutPadding().encodeToString(hashBytes);

            disclosures.add(disclosure);
            sdHashes.add(hash);
        }

        // JWT bauen mit _sd-Liste (nur Hashes, keine Rohdaten!); bewusst ohne sub (siehe Klassenkommentar)
        Instant issuedAt = clock.instant().truncatedTo(ChronoUnit.SECONDS);
        JWTClaimsSet.Builder payload = new JWTClaimsSet.Builder()
                .issuer(issuerUrls.credentialIssuer())
                .claim("vct", IpsCredentialType.VCT)
                .issueTime(Date.from(issuedAt))
                .expirationTime(Date.from(issuedAt.plus(validity)))
                .claim("_sd_alg", "sha-256")
                .claim("_sd", sdHashes);
        if (holderKey != null) {
            // only the public part (kty, crv, x, y), never d
            payload.claim("cnf", Map.of("jwk", holderKey.toPublicJWK().toJSONObject()));
        }

        // <issuer JWT>~<disclosure>~...~  (trailing "~": SD-JWT without key binding JWT)
        StringBuilder result = new StringBuilder(sign(header(SD_JWT_TYPE), payload.build()));
        for (String d : disclosures) {
            result.append('~').append(d);
        }
        return result.append('~').toString();
    }

    /** ES256 header with the public key as jwk; no kid, x5c, jku. */
    private JWSHeader header(JOSEObjectType type) {
        JWSHeader.Builder builder = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .jwk(signingKeyProvider.publicJwk());
        if (type != null) {
            builder.type(type);
        }
        return builder.build();
    }

    private String sign(JWSHeader header, JWTClaimsSet claims) throws JOSEException {
        SignedJWT signedJWT = new SignedJWT(header, claims);
        signedJWT.sign(signingKeyProvider.signer());
        return signedJWT.serialize();
    }

    private String mapResourceTypeToClaim(String resourceType) {
        return switch (resourceType) {
            case "AllergyIntolerance" -> "allergies";
            case "MedicationStatement", "MedicationRequest" -> "medications";
            case "Condition" -> "conditions";
            case "Immunization" -> "immunizations";
            case "Patient" -> "patient";
            case "Observation" -> "observations";
            default -> resourceType.toLowerCase();
        };
    }
}
