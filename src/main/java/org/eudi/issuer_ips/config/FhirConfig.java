package org.eudi.issuer_ips.config;

import ca.uhn.fhir.context.FhirContext;
import ca.uhn.fhir.rest.client.api.IGenericClient;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class FhirConfig {

    @Bean
    public FhirContext fhirContext() {
        return FhirContext.forR4();
    }

    /**
     * One FHIR client for the whole application, pointing at issuer.fhir.base-url.
     * Replaces the four newRestfulGenericClient(...) calls in PatientSummaryController.
     */
    @Bean
    public IGenericClient fhirClient(FhirContext fhirContext, FhirProperties fhirProperties) {
        return fhirContext.newRestfulGenericClient(fhirProperties.baseUrl());
    }
}
