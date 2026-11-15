package org.eudi.issuer_ips.testdata;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Local FHIR server for tests (no network). Serves the test files:
 *
 *   GET /fhir/metadata                  -> CapabilityStatement (HAPI asks once)
 *   GET /fhir/Patient/{id}/$summary     -> TestBundle with patientId {id}, e.g. 15, 1560, nhanes-110387
 *   GET /fhir/Patient/fhir-down/$summary -> 503 (server failure)
 *   anything else                        -> 404 OperationOutcome
 */
public final class FakeFhirServer implements AutoCloseable {

    /** Patient ID for which the server answers 503. */
    public static final String DOWN_PATIENT = "fhir-down";

    private static final Pattern SUMMARY = Pattern.compile("^/fhir/Patient/([^/]+)/\\$summary$");

    private static final String CAPABILITY_STATEMENT = """
            {"resourceType":"CapabilityStatement","status":"active","date":"2026-01-01",
             "kind":"instance","fhirVersion":"4.0.1","format":["json"]}""";

    private static final String NOT_FOUND = """
            {"resourceType":"OperationOutcome","issue":[{"severity":"error","code":"not-found",
             "diagnostics":"Resource Patient is not known"}]}""";

    private static final String UNAVAILABLE = """
            {"resourceType":"OperationOutcome","issue":[{"severity":"fatal","code":"transient",
             "diagnostics":"Service unavailable"}]}""";

    private final HttpServer server;
    private final List<String> summaryRequests = new CopyOnWriteArrayList<>();

    private FakeFhirServer(HttpServer server) {
        this.server = server;
    }

    public static FakeFhirServer start() {
        try {
            HttpServer http = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
            FakeFhirServer fake = new FakeFhirServer(http);
            http.createContext("/fhir", fake::handle);
            http.start();
            return fake;
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** Value for issuer.fhir.base-url. */
    public String baseUrl() {
        return "http://localhost:" + server.getAddress().getPort() + "/fhir";
    }

    /** Patient IDs for which $summary was requested, in order. */
    public List<String> summaryRequests() {
        return List.copyOf(summaryRequests);
    }

    public void clear() {
        summaryRequests.clear();
    }

    @Override
    public void close() {
        server.stop(0);
    }

    private void handle(HttpExchange exchange) throws IOException {
        String path = exchange.getRequestURI().getPath();
        if (path.endsWith("/metadata")) {
            send(exchange, 200, CAPABILITY_STATEMENT.getBytes(StandardCharsets.UTF_8));
            return;
        }
        Matcher m = SUMMARY.matcher(path);
        if (!m.matches()) {
            send(exchange, 404, NOT_FOUND.getBytes(StandardCharsets.UTF_8));
            return;
        }
        String patientId = m.group(1);
        summaryRequests.add(patientId);

        if (DOWN_PATIENT.equals(patientId)) {
            send(exchange, 503, UNAVAILABLE.getBytes(StandardCharsets.UTF_8));
            return;
        }
        Optional<TestBundle> bundle = Arrays.stream(TestBundle.values())
                .filter(b -> b.patientId().equals(patientId))
                .findFirst();
        if (bundle.isPresent()) {
            send(exchange, 200, bundle.get().bytes());
        } else {
            send(exchange, 404, NOT_FOUND.getBytes(StandardCharsets.UTF_8));
        }
    }

    private static void send(HttpExchange exchange, int status, byte[] body) throws IOException {
        exchange.getResponseHeaders().add("Content-Type", "application/fhir+json; charset=UTF-8");
        exchange.sendResponseHeaders(status, body.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(body);
        }
    }
}
