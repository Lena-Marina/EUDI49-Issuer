package org.eudi.issuer_ips.controller;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.io.IOException;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * issuer.fhir.base-url points to a local fake FHIR server; the request to
 * /issuer/Patient/{id}/$summary must arrive there (and therefore not at hapi.fhir.org).
 *
 * No network needed. The controller bean comes from the real Spring context,
 * MockMvc runs standalone on it (no extra test dependency).
 */
@SpringBootTest
class PatientSummaryControllerFhirUrlTest {

    private static final List<String> RECEIVED_PATHS = new CopyOnWriteArrayList<>();
    private static final HttpServer FAKE_FHIR = startFakeFhirServer();

    @DynamicPropertySource
    static void fhirBaseUrl(DynamicPropertyRegistry registry) {
        registry.add("issuer.fhir.base-url",
                () -> "http://localhost:" + FAKE_FHIR.getAddress().getPort() + "/fhir");
    }

    @Autowired
    private PatientSummaryController controller;

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        RECEIVED_PATHS.clear();
        mockMvc = MockMvcBuilders.standaloneSetup(controller).build();
    }

    @AfterAll
    static void stopServer() {
        FAKE_FHIR.stop(0);
    }

    @Test
    void summaryIsFetchedFromConfiguredServer() throws Exception {
        mockMvc.perform(get("/issuer/Patient/{id}/$summary", "test-123"))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("\"resourceType\": \"Bundle\"")));

        assertTrue(RECEIVED_PATHS.contains("/fhir/Patient/test-123/$summary"),
                "Fake-FHIR-Server hat keinen $summary-Aufruf erhalten: " + RECEIVED_PATHS);
    }

    // ---- fake FHIR server -------------------------------------------------

    private static final String CAPABILITY_STATEMENT = """
            {"resourceType":"CapabilityStatement","status":"active","date":"2026-01-01",
             "kind":"instance","fhirVersion":"4.0.1","format":["json"]}""";

    private static final String BUNDLE = """
            {"resourceType":"Bundle","type":"document"}""";

    private static HttpServer startFakeFhirServer() {
        try {
            HttpServer server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
            server.createContext("/fhir", PatientSummaryControllerFhirUrlTest::handle);
            server.start();
            return server;
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static void handle(HttpExchange exchange) throws IOException {
        String path = exchange.getRequestURI().getPath();
        RECEIVED_PATHS.add(path);
        // HAPI asks /metadata once per server before the first real request
        String body = path.endsWith("/metadata") ? CAPABILITY_STATEMENT : BUNDLE;
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/fhir+json; charset=UTF-8");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(bytes);
        }
    }
}
