package org.eudi.issuer_ips.model;

import java.time.Instant;

/**
 * Data for an issued authorization code.
 * Bound to the user identifier (userId), NOT to the patient ID).
 */
public record IssuedAuthorizationCode(
        String userId,
        String clientId,
        String redirectUri,
        String codeChallenge,
        String codeChallengeMethod,
        String authorizationDetails,
        Instant expiresAt
) {
    public boolean isExpiredAt(Instant now) {
        return !now.isBefore(expiresAt);
    }
}