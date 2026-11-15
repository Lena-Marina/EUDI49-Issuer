package org.eudi.issuer_ips.config;

import ca.uhn.fhir.rest.client.api.IGenericClient;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * FHIR base URL comes from application.properties.
 */
@SpringBootTest
class FhirPropertiesTest {

    @Autowired
    private FhirProperties fhirProperties;

    @Autowired
    private IGenericClient fhirClient;

    /** Default value is https://hapi.fhir.org/baseR4 (from application.properties). */
    @Test
    void defaultBaseUrlIsHapi() {
        assertEquals("https://hapi.fhir.org/baseR4", fhirProperties.baseUrl());
        assertEquals("https://hapi.fhir.org/baseR4", fhirClient.getServerBase());
    }

    /** Missing or empty property stops the start instead of silently using some server. */
    @Test
    void blankBaseUrlIsRejected() {
        assertThrows(IllegalStateException.class, () -> new FhirProperties(null));
        assertThrows(IllegalStateException.class, () -> new FhirProperties("  "));
    }

    /** No hard-coded FHIR URL anywhere in src/main/java (comments included). */
    @Test
    void noHardcodedFhirUrlInJavaCode() throws IOException {
        List<String> forbidden = List.of("hapi.fhir.org", "hl7-ips-server.hl7.org", "ips.health", "/baseR4");
        try (Stream<Path> files = Files.walk(Path.of("src/main/java"))) {
            List<String> hits = files
                    .filter(p -> p.toString().endsWith(".java"))
                    .flatMap(p -> {
                        try {
                            String text = Files.readString(p);
                            return forbidden.stream().filter(text::contains).map(f -> p + ": " + f);
                        } catch (IOException e) {
                            throw new RuntimeException(e);
                        }
                    })
                    .toList();
            assertTrue(hits.isEmpty(), "Hartcodierte FHIR-URL gefunden: " + hits);
        }
    }
}
