package org.eudi.issuer_ips.service;

import org.eudi.issuer_ips.config.IssuerProperties;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Check the real configuration from application.properties:
 * Test users -> User IDs and User IDs -> Patient IDs.
 */
@SpringBootTest
class MockAuthenticationProviderConfigTest {

    @Autowired
    private AuthenticationProvider authenticationProvider;

    @Autowired
    private IssuerProperties issuerProperties;

    @Test
    void annaLogsInAsUserAnna() {
        assertEquals(Optional.of("user-anna"), authenticationProvider.authenticate("anna", "geheim1"));
    }

    @Test
    void benLogsInAsUserBen() {
        assertEquals(Optional.of("user-ben"), authenticationProvider.authenticate("ben", "geheim2"));
    }

    @Test
    void wrongPasswordOrUnknownUserIsRejected() {
        assertTrue(authenticationProvider.authenticate("anna", "geheim2").isEmpty());
        assertTrue(authenticationProvider.authenticate("carla", "geheim1").isEmpty());
        assertTrue(authenticationProvider.authenticate("Anna", "geheim1").isEmpty());
    }

    @Test
    void patientMappingKeysKeepDash() {
        assertEquals("nhanes-110387", issuerProperties.patientMapping().get("user-anna"));
        assertEquals("nhanes-121623", issuerProperties.patientMapping().get("user-ben"));
    }
}