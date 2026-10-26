package org.eudi.issuer_ips.model;

import java.time.Instant;

/**
 * A pending authorization request to GET /authorize, waiting for the user to log in.
 * authorizationDetails is the unmodified JSON string from VC-K (can be null).
 */
public record PendingAuthorizationRequest(
        String clientId,
        String redirectUri,
        String state,
        String codeChallenge,
        String codeChallengeMethod,
        String authorizationDetails,
        Instant expiresAt
) {
    public boolean isExpiredAt(Instant now) {
        return !now.isBefore(expiresAt);
    }
}