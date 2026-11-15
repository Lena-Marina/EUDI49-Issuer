package org.eudi.issuer_ips.service;

/**
 * The IPS could not be fetched from the FHIR server.
 * Message is safe for error_description (no health data, no URLs with credentials).
 */
public class FhirSummaryException extends RuntimeException {

    public enum Reason {
        /** FHIR server answered 404: patient unknown there. */
        PATIENT_NOT_FOUND,
        /** FHIR server not reachable, other HTTP error or unreadable answer. */
        SERVER_UNAVAILABLE
    }

    private final Reason reason;

    public FhirSummaryException(Reason reason, String message, Throwable cause) {
        super(message, cause);
        this.reason = reason;
    }

    public Reason reason() {
        return reason;
    }
}
