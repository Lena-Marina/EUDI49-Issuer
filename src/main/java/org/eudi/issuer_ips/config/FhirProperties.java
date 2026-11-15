package org.eudi.issuer_ips.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * FHIR configuration with the prefix "issuer.fhir" from application.properties.
 *
 * baseUrl : base URL of the FHIR server that answers Patient/{id}/$summary
 *           (default value: see application.properties)
 *
 * There is deliberately no default value in Java: the URL lives only in the configuration.
 */
@ConfigurationProperties(prefix = "issuer.fhir")
public record FhirProperties(String baseUrl) {

    public FhirProperties {
        if (baseUrl == null || baseUrl.isBlank()) {
            throw new IllegalStateException("issuer.fhir.base-url has to be set");
        }
    }
}
