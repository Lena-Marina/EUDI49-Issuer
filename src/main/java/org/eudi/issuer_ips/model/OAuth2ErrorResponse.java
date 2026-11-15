package org.eudi.issuer_ips.model;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * OAuth 2.0 error response (RFC 6749, section 5.2): {"error": ..., "error_description": ...}.
 * VC-K reads error and error_description from JSON.
 * Used by /token and /credential.
 */
public record OAuth2ErrorResponse(
        @JsonProperty("error") String error,
        @JsonProperty("error_description") String errorDescription
) {
    // /token (RFC 6749)
    public static final String INVALID_REQUEST = "invalid_request";
    public static final String INVALID_GRANT = "invalid_grant";
    public static final String UNSUPPORTED_GRANT_TYPE = "unsupported_grant_type";

    // /credential: bearer token (RFC 6750, section 3.1)
    public static final String INVALID_TOKEN = "invalid_token";

    // /credential (OpenID4VCI 1.0, section 8.3.1.2)
    public static final String INVALID_CREDENTIAL_REQUEST = "invalid_credential_request";
    public static final String UNKNOWN_CREDENTIAL_IDENTIFIER = "unknown_credential_identifier";
    public static final String INVALID_PROOF = "invalid_proof";
    public static final String CREDENTIAL_REQUEST_DENIED = "credential_request_denied";

    // FHIR server not reachable or patient unknown there (RFC 6749 style)
    public static final String SERVER_ERROR = "server_error";
}
