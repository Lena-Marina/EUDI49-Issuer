package org.eudi.issuer_ips.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

/**
 * Issued credential, prefix "issuer.credential" in application.properties.
 *
 * validity : exp - iat of the IPS SD-JWT (ISO-8601 duration, e.g. P30D)
 */
@ConfigurationProperties(prefix = "issuer.credential")
public record CredentialProperties(Duration validity) {

    public CredentialProperties {
        if (validity == null || validity.isZero() || validity.isNegative()) {
            throw new IllegalStateException("issuer.credential.validity muss eine positive Dauer sein (z. B. P30D)");
        }
    }
}
