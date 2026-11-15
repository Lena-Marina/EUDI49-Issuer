package org.eudi.issuer_ips.service;

import org.eudi.issuer_ips.config.IssuerProperties;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * User identifier -> patient ID from issuer.patient-mapping.
 */
class ConfigPatientIdResolverTest {

    private final PatientIdResolver resolver = new ConfigPatientIdResolver(new IssuerProperties(
            new IssuerProperties.WalletClient("client", "redirect"),
            null,
            Map.of("user-anna", "nhanes-110387", "user-ben", "nhanes-121623")));

    @Test
    void knownUsersResolveToTheirPatientIds() {
        assertEquals(Optional.of("nhanes-110387"), resolver.resolvePatientId("user-anna"));
        assertEquals(Optional.of("nhanes-121623"), resolver.resolvePatientId("user-ben"));
    }

    @Test
    void unknownBlankOrMissingUserGivesEmpty() {
        assertEquals(Optional.empty(), resolver.resolvePatientId("user-unknown"));
        assertEquals(Optional.empty(), resolver.resolvePatientId(""));
        assertEquals(Optional.empty(), resolver.resolvePatientId(null));
    }
}
