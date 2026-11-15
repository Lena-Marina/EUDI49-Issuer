package org.eudi.issuer_ips.service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.eudi.issuer_ips.config.IssuerUrlProperties;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Creates JWT / SD-JWT from an IPS bundle.
 *
 * Signed with ES256 (key from SigningKeyProvider), public key as "jwk"
 * in the JWS header, iss = issuer.base-url (same value as credential_issuer).
 * Not yet part of this class: vct, cnf, exp policy
 */
@Service
public class JwtService {

    /** typ of an SD-JWT VC, as expected by VC-K 5.10.1. */
    static final JOSEObjectType SD_JWT_TYPE = new JOSEObjectType("dc+sd-jwt");

    private final SigningKeyProvider signingKeyProvider;
    private final IssuerUrlProperties issuerUrls;

    public JwtService(SigningKeyProvider signingKeyProvider, IssuerUrlProperties issuerUrls) {
        this.signingKeyProvider = signingKeyProvider;
        this.issuerUrls = issuerUrls;
    }

    /** Simple JWT with the whole bundle (test endpoint /issuer/Patient/{id}/jwt). */
    public String createJwt(String patientId, String fhirJson) throws Exception {

        ObjectMapper mapper = new ObjectMapper();
        // DEBUG
        System.out.println("FHIR JSON START:");
        System.out.println(fhirJson.substring(0, Math.min(500, fhirJson.length())));
        System.out.println("FHIR JSON END");

        Map<String, Object> fhirObject  = mapper.readValue(fhirJson, new TypeReference<Map<String, Object>>(){});

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(issuerUrls.credentialIssuer())
                .subject(patientId)
                .issueTime(new Date())
                .expirationTime(Date.from(
                        Instant.now().plusSeconds(3600)
                ))
                .claim("fhir", fhirObject)
                .build();

        // plain JWT: no typ dc+sd-jwt, it is not an SD-JWT VC
        return sign(header(null), claims);
    }

    public String createSdJwt(String patientId, String fhirJson) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        Map<String, Object> fhirObject = mapper.readValue(fhirJson, new TypeReference<>() {});

        // FHIR Bundle entries extrahieren
        List<Map<String, Object>> entries = (List<Map<String, Object>>) fhirObject.get("entry");

        // DEBUG
        System.out.println("Entries count: " + (entries != null ? entries.size() : "null"));
        if (entries != null) {
            for (Map<String, Object> entry : entries) {
                Map<String, Object> resource = (Map<String, Object>) entry.get("resource");
                System.out.println("Resource: " + (resource != null ? resource.get("resourceType") : "null"));
            }
        }

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

        // JWT bauen mit _sd-Liste (nur Hashes, keine Rohdaten!)
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(issuerUrls.credentialIssuer())
                .subject(patientId)
                .issueTime(new Date())
                .expirationTime(Date.from(Instant.now().plusSeconds(3600)))
                .claim("_sd_alg", "sha-256")
                .claim("_sd", sdHashes)
                .build();

        // Alle Disclosures mit ~ anhängen
        String result = sign(header(SD_JWT_TYPE), claims);
        for (String d : disclosures) result += "~" + d;
        return result;
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
