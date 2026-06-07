package org.eudi.issuer_ips.service;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;


@Service
public class JwtService {
    public String createJwt(String patientId, String fhirJson) throws Exception {

        ObjectMapper mapper = new ObjectMapper();
        // DEBUG
        System.out.println("FHIR JSON START:");
        System.out.println(fhirJson.substring(0, Math.min(500, fhirJson.length())));
        System.out.println("FHIR JSON END");

        Map<String, Object> fhirObject  = mapper.readValue(fhirJson, new TypeReference<Map<String, Object>>(){});

        JWSSigner signer = new MACSigner("12345678901234567890123456789012");

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer("http://localhost:8080")
                .subject(patientId)
                .issueTime(new Date())
                .expirationTime(Date.from(
                        Instant.now().plusSeconds(3600)
                ))
                .claim("fhir", fhirObject)
                .build();

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader(JWSAlgorithm.HS256),
                claims
        );

        signedJWT.sign(signer);

        return signedJWT.serialize();
    }

    /*public String createSdJwt(String patientId, String fhirJson) throws Exception {

        ObjectMapper objectMapper = new ObjectMapper();

        Map<String, Object> fhirObject =
                objectMapper.readValue(fhirJson, new TypeReference<Map<String, Object>>() {});

        String salt = UUID.randomUUID().toString();

        List<Object> disclosureArray = List.of(
                salt,
                "fhir",
                fhirObject
        );

        String disclosureJson =
                objectMapper.writeValueAsString(disclosureArray);

        String disclosure = Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(disclosureJson.getBytes(StandardCharsets.UTF_8));

        byte[] hashBytes = MessageDigest.getInstance("SHA-256")
                .digest(disclosure.getBytes(StandardCharsets.US_ASCII));

        String disclosureHash = Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(hashBytes);

        JWSSigner signer =
                new MACSigner("12345678901234567890123456789012");

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer("http://localhost:8080")
                .subject(patientId)
                .issueTime(new Date())
                .expirationTime(Date.from(
                        Instant.now().plusSeconds(3600)
                ))
                .claim("_sd_alg", "sha-256")
                .claim("_sd", List.of(disclosureHash))
                .build();

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader(JWSAlgorithm.HS256),
                claims
        );

        signedJWT.sign(signer);

        return signedJWT.serialize() + "~" + disclosure;
    }*/


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
        JWSSigner signer = new MACSigner("12345678901234567890123456789012");
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer("http://localhost:8080")
                .subject(patientId)
                .issueTime(new Date())
                .expirationTime(Date.from(Instant.now().plusSeconds(3600)))
                .claim("_sd_alg", "sha-256")
                .claim("_sd", sdHashes)
                .build();

        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims);
        signedJWT.sign(signer);

        // Alle Disclosures mit ~ anhängen
        String result = signedJWT.serialize();
        for (String d : disclosures) result += "~" + d;
        return result;
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
