package org.eudi.issuer_ips.service;

import org.eudi.issuer_ips.config.IssuerProperties;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Map;
import java.util.Optional;

/**
 * Mock-Login for the hardcoded testusers-table in application.properties
 * (issuer.mock-users.<username>.password / .user-id).
 */
@Service
public class MockAuthenticationProvider implements AuthenticationProvider {

    private final Map<String, IssuerProperties.MockUser> users;

    public MockAuthenticationProvider(IssuerProperties issuerProperties) {
        this.users = issuerProperties.mockUsers();
    }

    @Override
    public Optional<String> authenticate(String username, String password) {
        if (username == null || password == null) {
            return Optional.empty();
        }
        IssuerProperties.MockUser user = users.get(username);
        if (user == null || user.password() == null || user.userId() == null) {
            return Optional.empty();
        }
        // time-constant comparison
        boolean matches = MessageDigest.isEqual(
                user.password().getBytes(StandardCharsets.UTF_8),
                password.getBytes(StandardCharsets.UTF_8));
        return matches ? Optional.of(user.userId()) : Optional.empty();
    }
}