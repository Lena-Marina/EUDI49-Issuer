package org.eudi.issuer_ips.testdata;

import ca.uhn.fhir.context.FhirContext;
import ca.uhn.fhir.parser.IParser;
import ca.uhn.fhir.parser.StrictErrorHandler;
import org.hl7.fhir.r4.model.Bundle;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The three test bundles are in the repository with LF line endings,
 * each has a README (server, URL, Bundle.timestamp / retrieval date, size),
 * and all of them parse with FhirContext.forR4() without errors.
 *
 * No Spring context, no network.
 */
class TestdataFilesTest {

    /** FhirContext is expensive to create; one for the whole class. */
    private static final FhirContext FHIR = FhirContext.forR4();

    private static final Pattern BUNDLE_TIMESTAMP =
            Pattern.compile("\"timestamp\"\\s*:\\s*\"([^\"]+)\"");

    // ---- Files in the repository with LF line endings ------------------

    /** File is on the test classpath and contains no CR byte (and no BOM). */
    @ParameterizedTest
    @EnumSource(TestBundle.class)
    void fileIsPresentWithLfLineEndingsOnly(TestBundle bundle) {
        byte[] bytes = bundle.bytes();

        assertTrue(bytes.length > 0, bundle.fileName() + " ist leer");
        int crCount = 0;
        for (byte b : bytes) {
            if (b == '\r') {
                crCount++;
            }
        }
        assertEquals(0, crCount, bundle.fileName() + " enthält CR-Zeichen (Windows-Zeilenenden)");
        assertFalse(bytes.length >= 3
                        && (bytes[0] & 0xFF) == 0xEF && (bytes[1] & 0xFF) == 0xBB && (bytes[2] & 0xFF) == 0xBF,
                bundle.fileName() + " beginnt mit einem UTF-8-BOM");
    }

    /** .gitattributes forces LF for the test data, so a Windows checkout keeps the bytes. */
    @Test
    void gitattributesForcesLfForTestdata() throws IOException {
        Path gitattributes = Path.of(".gitattributes");
        assertTrue(Files.exists(gitattributes), ".gitattributes fehlt im Projekt-Root");

        boolean hasRule = Files.readAllLines(gitattributes).stream()
                .map(String::trim)
                .anyMatch(line -> line.startsWith("src/test/resources/testdata/")
                        && line.contains("text")
                        && line.contains("eol=lf"));
        assertTrue(hasRule, ".gitattributes enthält keine eol=lf-Regel für src/test/resources/testdata/");
    }

    // ---- README with server, URL, Bundle.timestamp / date, size --------

    /**
     * README names server and URL, repeats the actual Bundle.timestamp of the file
     * and its actual byte size, so README and file cannot silently drift apart.
     */
    @ParameterizedTest
    @EnumSource(TestBundle.class)
    void readmeDescribesTheFile(TestBundle bundle) {
        String readme = bundle.readme();
        String json = bundle.json();

        String expectedUrl = switch (bundle) {
            case P15 -> "https://hl7-ips-server.hl7.org/fhir/Patient/15/$summary";
            case P1560 -> "https://hl7-ips-server.hl7.org/fhir/Patient/1560/$summary";
            case NHANES_110387 -> "https://hapi.fhir.org/baseR4/Patient/nhanes-110387/$summary";
        };
        String expectedServer = expectedUrl.replaceFirst("^https://([^/]+)/.*$", "$1");

        Matcher m = BUNDLE_TIMESTAMP.matcher(json);
        assertTrue(m.find(), bundle.fileName() + ": kein Bundle.timestamp gefunden");
        String timestamp = m.group(1);

        assertAll(bundle.readmeFileName(),
                () -> assertTrue(readme.contains("Server"), "Zeile 'Server' fehlt"),
                () -> assertTrue(readme.contains(expectedServer), "Server " + expectedServer + " fehlt"),
                () -> assertTrue(readme.contains(expectedUrl), "URL " + expectedUrl + " fehlt"),
                () -> assertTrue(readme.contains(timestamp), "Bundle.timestamp " + timestamp + " fehlt"),
                () -> assertTrue(readme.contains("Abrufdatum") && readme.contains(timestamp.substring(0, 10)),
                        "Abrufdatum " + timestamp.substring(0, 10) + " fehlt"),
                () -> assertTrue(readme.contains(bundle.bytes().length + " Byte"),
                        "Größe '" + bundle.bytes().length + " Byte' fehlt (README passt nicht zur Datei)"));
    }

    // ---- Parses with FhirContext.forR4() without errors -----------------

    /**
     * Strict parser: every unknown element, invalid value or broken contained
     * reference is an error. The entry count guards against a replaced file.
     */
    @ParameterizedTest
    @EnumSource(TestBundle.class)
    void parsesWithStrictR4Parser(TestBundle bundle) {
        IParser parser = FHIR.newJsonParser();
        parser.setParserErrorHandler(new StrictErrorHandler());

        Bundle parsed = assertDoesNotThrow(
                () -> parser.parseResource(Bundle.class, bundle.json()),
                bundle.fileName() + " lässt sich nicht fehlerfrei parsen");

        assertEquals(Bundle.BundleType.DOCUMENT, parsed.getType(), bundle.fileName() + ": Bundle.type");
        assertEquals(bundle.entryCount(), parsed.getEntry().size(), bundle.fileName() + ": Anzahl Einträge");
        assertTrue(parsed.getEntry().stream().allMatch(Bundle.BundleEntryComponent::hasResource),
                bundle.fileName() + ": Eintrag ohne Ressource");
        assertEquals("Composition",
                parsed.getEntryFirstRep().getResource().fhirType(),
                bundle.fileName() + ": erster Eintrag ist keine Composition");
    }
}
