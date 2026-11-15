package org.eudi.issuer_ips.service;

import org.eudi.issuer_ips.model.IssuedAccessToken;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Issues and checks access tokens (POST /token -> POST /credential).
 *
 * Opaque random tokens, only in memory: after a restart all tokens are gone.
 * A token stores the user identifier and the expiry time - no patient ID.
 */
@Service
public class AccessTokenService {

    public static final Duration ACCESS_TOKEN_TTL = Duration.ofMinutes(10);

    private final Clock clock;
    private final SecureRandom secureRandom = new SecureRandom();
    private final ConcurrentHashMap<String, IssuedAccessToken> tokens = new ConcurrentHashMap<>();

    public AccessTokenService(Clock clock) {
        this.clock = clock;
    }

    /** Issues a new access token for the given user identifier. */
    public String issue(String userId) {
        if (userId == null || userId.isBlank()) {
            throw new IllegalArgumentException("userId fehlt");
        }
        purgeExpired();
        String token = randomToken();
        tokens.put(token, new IssuedAccessToken(userId, clock.instant().plus(ACCESS_TOKEN_TTL)));
        return token;
    }

    /**
     * For /credential: checks an access token (value without "Bearer ")
     * and returns the user identifier, or empty if unknown or expired.
     * The token stays valid until it expires (several credential requests are allowed).
     */
    public Optional<String> resolveUserId(String accessToken) {
        if (accessToken == null || accessToken.isBlank()) {
            return Optional.empty();
        }
        IssuedAccessToken issued = tokens.get(accessToken);
        if (issued == null) {
            return Optional.empty();
        }
        if (issued.isExpiredAt(clock.instant())) {
            tokens.remove(accessToken, issued);
            return Optional.empty();
        }
        return Optional.of(issued.userId());
    }

    /** expires_in for the token response, in whole seconds. */
    public long expiresInSeconds() {
        return ACCESS_TOKEN_TTL.toSeconds();
    }

    private void purgeExpired() {
        Instant now = clock.instant();
        tokens.values().removeIf(t -> t.isExpiredAt(now));
    }

    /** 32 Byte SecureRandom, Base64url without padding (43 chars), like the authorization code. */
    private String randomToken() {
        byte[] bytes = new byte[32];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
