package org.eudi.issuer_ips.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Public base URL of this issuer (property "issuer.base-url").
 *
 * Single source for:
 *  - credential_issuer (credential issuer metadata)
 *  - issuer           (authorization server metadata)
 *  - iss              (in every issued SD-JWT)
 *  - the endpoint URLs announced in the metadata
 *
 * On the Android emulator the host is reachable as 10.0.2.2, so the default
 * in application.properties is http://10.0.2.2:8080.
 */
@ConfigurationProperties(prefix = "issuer")
public record IssuerUrlProperties(String baseUrl) {

    public IssuerUrlProperties {
        if (baseUrl == null || baseUrl.isBlank()) {
            throw new IllegalStateException("issuer.base-url muss gesetzt sein");
        }
        // "http://host:8080/" and "http://host:8080" must give the same iss
        while (baseUrl.endsWith("/")) {
            baseUrl = baseUrl.substring(0, baseUrl.length() - 1);
        }
    }

    /** credential_issuer in the metadata and iss in the SD-JWT. */
    public String credentialIssuer() {
        return baseUrl;
    }

    public String authorizationEndpoint() {
        return baseUrl + "/authorize";
    }

    public String tokenEndpoint() {
        return baseUrl + "/token";
    }

    public String credentialEndpoint() {
        return baseUrl + "/credential";
    }
}
