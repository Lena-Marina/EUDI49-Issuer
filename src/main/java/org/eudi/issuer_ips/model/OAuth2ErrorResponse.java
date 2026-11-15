package org.eudi.issuer_ips.model;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * OAuth 2.0 error response (RFC 6749, section 5.2): {"error": ..., "error_description": ...}.
 * VC-K reads error and error_description from JSON.
 */
public record OAuth2ErrorResponse(
        @JsonProperty("error") String error,
        @JsonProperty("error_description") String errorDescription
) {
    public static final String INVALID_REQUEST = "invalid_request";
    public static final String INVALID_GRANT = "invalid_grant";
    public static final String UNSUPPORTED_GRANT_TYPE = "unsupported_grant_type";
}
