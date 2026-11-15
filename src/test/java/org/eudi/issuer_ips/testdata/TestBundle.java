package org.eudi.issuer_ips.testdata;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;

/**
 * The three fixed IPS test bundles from src/test/resources/testdata
 *
 * patientId is the ID the bundle was fetched with ($summary), so fake FHIR
 * servers in later tests can serve the file under the same path.
 */
public enum TestBundle {

    /** HL7 IPS server, Patient 15: main case, urn:uuid only, 14 sections. */
    P15("15.json", "15", 18),

    /** HL7 IPS server, Patient 1560: minimal case, 3 placeholders. */
    P1560("1560.json", "1560", 6),

    /** hapi.fhir.org: mixed references (relative + urn:uuid), Bundle-uv-ips. */
    NHANES_110387("nhanes-110387.json", "nhanes-110387", 39);

    private static final String DIR = "/testdata/";

    private final String fileName;
    private final String patientId;
    private final int entryCount;

    TestBundle(String fileName, String patientId, int entryCount) {
        this.fileName = fileName;
        this.patientId = patientId;
        this.entryCount = entryCount;
    }

    public String fileName() {
        return fileName;
    }

    public String patientId() {
        return patientId;
    }

    /** Number of Bundle.entry as measured on 15.11.2026 (see README). */
    public int entryCount() {
        return entryCount;
    }

    /** File name of the README next to the bundle, e.g. 15.README.md. */
    public String readmeFileName() {
        return fileName.replace(".json", ".README.md");
    }

    /** Raw bytes exactly as stored in the repository. */
    public byte[] bytes() {
        return read(DIR + fileName);
    }

    /** Bundle as UTF-8 JSON string. */
    public String json() {
        return new String(bytes(), StandardCharsets.UTF_8);
    }

    public String readme() {
        return new String(read(DIR + readmeFileName()), StandardCharsets.UTF_8);
    }

    private static byte[] read(String classpathLocation) {
        try (InputStream in = TestBundle.class.getResourceAsStream(classpathLocation)) {
            if (in == null) {
                throw new IllegalStateException("Testdatei fehlt im Classpath: " + classpathLocation);
            }
            return in.readAllBytes();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
