package org.eudi.issuer_ips.model;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/**
 * Successful response of POST /token, as expected by VC-K 5.10.1.
 *
 * Deliberately WITHOUT scope, refresh_token and c_nonce
 * authorization_details is mandatory for VC-K: without it (and without scope
 * in the metadata) VC-K throws InvalidToken.
 */
public record TokenResponse(
        @JsonProperty("access_token") String accessToken,
        @JsonProperty("token_type") String tokenType,
        @JsonProperty("expires_in") long expiresIn,
        @JsonProperty("authorization_details") List<AuthorizationDetail> authorizationDetails
) {

    /**
     * Spring logs response bodies on DEBUG (logging.level.org.springframework.web=DEBUG):
     * the access token must not appear in the log.
     */
    @Override
    public String toString() {
        return "TokenResponse[accessToken=***, tokenType=" + tokenType + ", expiresIn=" + expiresIn
                + ", authorizationDetails=" + authorizationDetails + "]";
    }

    /**
     * One entry of authorization_details. VC-K only evaluates entries with
     * type "openid_credential"; with credential_identifiers it later sends
     * credential_identifier in the credential request.
     */
    public record AuthorizationDetail(
            @JsonProperty("type") String type,
            @JsonProperty("credential_configuration_id") String credentialConfigurationId,
            @JsonProperty("credential_identifiers") List<String> credentialIdentifiers
    ) {
    }
}
