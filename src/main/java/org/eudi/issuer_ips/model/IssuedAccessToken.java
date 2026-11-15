package org.eudi.issuer_ips.model;

import java.time.Instant;

/**
 * Data stored for an issued access token.
 * Bound to the user identifier (userId), NOT to the patient ID:
 * the patient ID is resolved only in /credential
 */
public record IssuedAccessToken(
        String userId,
        Instant expiresAt
) {
    public boolean isExpiredAt(Instant now) {
        return !now.isBefore(expiresAt);
    }
}
