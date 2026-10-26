package org.eudi.issuer_ips.service;

import java.util.Optional;

/**
 * Authentication Provider: "Login -> User Identifier".
 * Now: MockAuthenticationProvider (Configuration). Planned: ID Austria.
 */
@FunctionalInterface
public interface AuthenticationProvider {

    /**
     * @return the user identifier upon successful login, otherwise Optional.empty()
     */
    Optional<String> authenticate(String username, String password);
}