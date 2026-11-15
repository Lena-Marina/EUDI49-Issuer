package org.eudi.issuer_ips.service;

import org.eudi.issuer_ips.model.IssuedAuthorizationCode;
import org.eudi.issuer_ips.model.PendingAuthorizationRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Saves pending login requests (GET /authorize -> POST /authorize)
 * and issued authorization codes (POST /authorize -> POST /token).
 *
 * Only in memory: after a restart of the issuer, all requests and codes are gone.
 */
@Service
public class AuthorizationCodeService {

    public static final Duration LOGIN_REQUEST_TTL = Duration.ofMinutes(10);
    public static final Duration CODE_TTL = Duration.ofMinutes(5);

    private final Clock clock;
    private final SecureRandom secureRandom = new SecureRandom();
    private final ConcurrentHashMap<String, PendingAuthorizationRequest> pendingRequests = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, IssuedAuthorizationCode> codes = new ConcurrentHashMap<>();

    /** Used by Spring; the Clock comes from ClockConfig (replaceable in tests). */
    @Autowired
    public AuthorizationCodeService(Clock clock) {
        this.clock = clock;
    }

    /** System clock (kept for existing tests without Spring context). */
    public AuthorizationCodeService() {
        this(Clock.systemUTC());
    }

    /**
     * Saves a verified /authorize request.
     * @return random requestId for the hidden form field
     */
    public String createPendingRequest(String clientId,
                                       String redirectUri,
                                       String state,
                                       String codeChallenge,
                                       String codeChallengeMethod,
                                       String authorizationDetails) {
        purgeExpired();
        String requestId = randomToken();
        pendingRequests.put(requestId, new PendingAuthorizationRequest(
                clientId, redirectUri, state, codeChallenge, codeChallengeMethod, authorizationDetails,
                clock.instant().plus(LOGIN_REQUEST_TTL)));
        return requestId;
    }

    /**
     * Returns the pending request without consuming it (for reattempt after failed login).
     */
    public Optional<PendingAuthorizationRequest> findPendingRequest(String requestId) {
        if (requestId == null) {
            return Optional.empty();
        }
        PendingAuthorizationRequest request = pendingRequests.get(requestId);
        if (request == null) {
            return Optional.empty();
        }
        if (request.isExpiredAt(clock.instant())) {
            pendingRequests.remove(requestId, request);
            return Optional.empty();
        }
        return Optional.of(request);
    }

    /**
     * Process the pending request (atomically) and generate an authorization code bound to the user identifier.
     * At most one code will be issued per requestId.
     */
    public Optional<String> issueCode(String requestId, String userId) {
        if (requestId == null || userId == null) {
            return Optional.empty();
        }
        PendingAuthorizationRequest request = pendingRequests.remove(requestId);
        if (request == null || request.isExpiredAt(clock.instant())) {
            return Optional.empty();
        }
        purgeExpired();
        String code = randomToken();
        codes.put(code, new IssuedAuthorizationCode(
                userId,
                request.clientId(),
                request.redirectUri(),
                request.codeChallenge(),
                request.codeChallengeMethod(),
                request.authorizationDetails(),
                clock.instant().plus(CODE_TTL)));
        return Optional.of(code);
    }

    /**
     * Uses the authorization code exactly once (atomically removed).
     * The verification of PKCE, redirect_uri and client_id is done in /token.
     */
    public Optional<IssuedAuthorizationCode> redeemCode(String code) {
        if (code == null) {
            return Optional.empty();
        }
        IssuedAuthorizationCode issued = codes.remove(code);
        if (issued == null || issued.isExpiredAt(clock.instant())) {
            return Optional.empty();
        }
        return Optional.of(issued);
    }

    private void purgeExpired() {
        Instant now = clock.instant();
        pendingRequests.values().removeIf(r -> r.isExpiredAt(now));
        codes.values().removeIf(c -> c.isExpiredAt(now));
    }

    /** 32 Byte SecureRandom, Base64url without Padding (43 chars). */
    private String randomToken() {
        byte[] bytes = new byte[32];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}