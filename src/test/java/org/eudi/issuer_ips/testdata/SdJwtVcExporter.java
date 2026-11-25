package org.eudi.issuer_ips.testdata;

import ca.uhn.fhir.context.FhirContext;
import com.nimbusds.jose.jwk.ECKey;
import org.eudi.issuer_ips.ProofJwts;
import org.eudi.issuer_ips.config.IssuerUrlProperties;
import org.eudi.issuer_ips.service.JwtService;
import org.eudi.issuer_ips.service.SigningKeyProvider;
import org.hl7.fhir.r4.model.Bundle;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;

/**
 * NOT a regular test (name does not end with "Test", ./mvnw test skips it).
 * Writes one SD-JWT VC per test bundle for the harness, which checks them with
 * Valera's ValidatorSdJwt(verifyJwsObject = VerifyJwsObject(publicKeyLookup = ...)):
 *
 *   ./mvnw -q test -Dtest=SdJwtVcExporter
 *   ./mvnw -q test -Dtest=SdJwtVcExporter -Dexport.iss=http://10.0.2.2:8080
 *
 * Output in target/export/:
 *   15.sdjwt, 1560.sdjwt, nhanes-110387.sdjwt  - exactly as /credential would issue them
 *                                                (FHIR JSON re-encoded by HAPI like FhirSummaryService)
 *   holder-public-jwk.json                      - key in cnf.jwk of all three (one holder)
 *   README.txt                                  - what to check
 *
 * Real clock, validity 30 days: the files are valid for 30 days after export.
 */
class SdJwtVcExporter {

    @Test
    void export() throws Exception {
        String iss = System.getProperty("export.iss", "http://10.0.2.2:8080");
        JwtService jwtService = new JwtService(new SigningKeyProvider(), new IssuerUrlProperties(iss));
        FhirContext fhir = FhirContext.forR4();
        ECKey holder = ProofJwts.newKey();

        Path dir = Path.of("target", "export");
        Files.createDirectories(dir);

        for (TestBundle bundle : TestBundle.values()) {
            Bundle parsed = fhir.newJsonParser().parseResource(Bundle.class, bundle.json());
            String fhirJson = fhir.newJsonParser().encodeResourceToString(parsed);
            String sdJwt = jwtService.createSdJwt(fhirJson, holder);
            Path file = dir.resolve(bundle.fileName().replace(".json", ".sdjwt"));
            Files.writeString(file, sdJwt, StandardCharsets.US_ASCII);
            System.out.println(file + " (" + sdJwt.length() + " Zeichen)");
        }
        Files.writeString(dir.resolve("holder-public-jwk.json"), holder.toPublicJWK().toJSONString(),
                StandardCharsets.UTF_8);
        Files.writeString(dir.resolve("README.txt"), """
                SD-JWT VCs des Issuers fuer den Pruef-Harness.
                Exportiert: %s, iss = %s, Gueltigkeit 30 Tage.

                Pruefen mit Valeras Konfiguration (VckModule.kt:42):
                  ValidatorSdJwt(verifyJwsObject = VerifyJwsObject(publicKeyLookup = ...))
                  -> verifySdJwt fuer alle drei Dateien erfolgreich
                  -> Issuer-Schluessel = jwk im JWS-Header
                  -> cnf.jwk = holder-public-jwk.json
                  -> vct = urn:eu.europa.ec.eudi:ips:1
                """.formatted(Instant.now(), iss), StandardCharsets.UTF_8);
        System.out.println("==== exportiert nach " + dir.toAbsolutePath() + " ====");
    }
}
