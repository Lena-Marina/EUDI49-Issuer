package org.eudi.issuer_ips.service;

import org.eudi.issuer_ips.config.IssuerProperties;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.Optional;

/**
 * Mock for PatientIdResolver: table issuer.patient-mapping.<user-id>=<patient-id>
 * from application.properties.
 */
@Service
public class ConfigPatientIdResolver implements PatientIdResolver {

    private final Map<String, String> mapping;

    public ConfigPatientIdResolver(IssuerProperties issuerProperties) {
        this.mapping = issuerProperties.patientMapping();
    }

    @Override
    public Optional<String> resolvePatientId(String userId) {
        if (userId == null || userId.isBlank()) {
            return Optional.empty();
        }
        String patientId = mapping.get(userId);
        return (patientId == null || patientId.isBlank()) ? Optional.empty() : Optional.of(patientId);
    }
}
