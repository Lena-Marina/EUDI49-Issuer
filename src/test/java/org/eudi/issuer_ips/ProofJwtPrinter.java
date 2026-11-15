package org.eudi.issuer_ips;

import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.JSONObjectUtils;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * NOT a regular test (name does not end with "Test", so ./mvnw test skips it).
 * Prints a fresh, valid proof JWT for manual curl checks of /credential:
 *
 *   ./mvnw -q test -Dtest=ProofJwtPrinter
 *   ./mvnw -q test -Dtest=ProofJwtPrinter -Dproof.aud=http://10.0.2.2:8080
 *
 * aud must be issuer.base-url of the running issuer (default http://10.0.2.2:8080).
 * The proof is valid for 5 minutes. Output files:
 *   target/proof.jwt                  - the proof JWT
 *   target/credential-request.json    - complete request body for POST /credential
 *   target/holder-public-jwk.json     - holder public key (to compare with cnf.jwk in US15)
 */
class ProofJwtPrinter {

    @Test
    void printProof() throws IOException {
        String audience = System.getProperty("proof.aud", "http://10.0.2.2:8080");
        ECKey holder = ProofJwts.newKey();
        String proof = ProofJwts.proof(holder, audience, Instant.now()).build();

        String requestBody = JSONObjectUtils.toJSONString(Map.of(
                "credential_identifier", "urn:eu.europa.ec.eudi:ips:1",
                "proofs", Map.of("jwt", List.of(proof))));

        Path target = Path.of("target");
        Files.createDirectories(target);
        Files.writeString(target.resolve("proof.jwt"), proof, StandardCharsets.US_ASCII);
        Files.writeString(target.resolve("credential-request.json"), requestBody, StandardCharsets.UTF_8);
        Files.writeString(target.resolve("holder-public-jwk.json"), holder.toPublicJWK().toJSONString(),
                StandardCharsets.UTF_8);

        System.out.println("==== PROOF (aud=" + audience + ", gültig 5 Min.) ====");
        System.out.println(proof);
        System.out.println("==== geschrieben: target/proof.jwt, target/credential-request.json, target/holder-public-jwk.json ====");
    }
}
