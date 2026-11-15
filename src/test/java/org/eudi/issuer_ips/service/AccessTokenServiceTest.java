package org.eudi.issuer_ips.service;

import org.eudi.issuer_ips.MutableClock;
import org.eudi.issuer_ips.model.IssuedAccessToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.lang.reflect.RecordComponent;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Token store holds user identifier and expiry time, no patient ID;
 * expiry tested with an injected Clock. Pure JUnit.
 */
class AccessTokenServiceTest {

    private MutableClock clock;
    private AccessTokenService service;

    @BeforeEach
    void setUp() {
        clock = new MutableClock(Instant.parse("2026-11-15T12:00:00Z"));
        service = new AccessTokenService(clock);
    }

    @Test
    void issuedTokenResolvesToUserId() {
        String token = service.issue("user-anna");
        assertEquals(Optional.of("user-anna"), service.resolveUserId(token));
        // can be used more than once while valid (several credential requests)
        assertEquals(Optional.of("user-anna"), service.resolveUserId(token));
    }

    @Test
    void tokenIsValidUntilJustBeforeTtl() {
        String token = service.issue("user-anna");
        clock.advance(AccessTokenService.ACCESS_TOKEN_TTL.minusSeconds(1));
        assertTrue(service.resolveUserId(token).isPresent());
    }

    @Test
    void tokenExpiresExactlyAtTtl() {
        String token = service.issue("user-anna");
        clock.advance(AccessTokenService.ACCESS_TOKEN_TTL);
        assertTrue(service.resolveUserId(token).isEmpty());
        // and stays invalid when the clock is set back
        clock.advance(Duration.ofHours(-1));
        assertTrue(service.resolveUserId(token).isEmpty());
    }

    @Test
    void unknownOrMissingTokenIsRejected() {
        service.issue("user-anna");
        assertTrue(service.resolveUserId("gibt-es-nicht").isEmpty());
        assertTrue(service.resolveUserId(null).isEmpty());
        assertTrue(service.resolveUserId("").isEmpty());
    }

    @Test
    void tokensAreRandomAnd43Chars() {
        String a = service.issue("user-anna");
        String b = service.issue("user-anna");
        assertNotEquals(a, b);
        assertEquals(43, a.length());
    }

    @Test
    void expiresInIsWholeSeconds() {
        assertEquals(600, service.expiresInSeconds());
    }

    @Test
    void storeHoldsOnlyUserIdAndExpiry() {
        List<String> components = Arrays.stream(IssuedAccessToken.class.getRecordComponents())
                .map(RecordComponent::getName)
                .toList();
        assertEquals(List.of("userId", "expiresAt"), components);
    }

    @Test
    void blankUserIdIsRejected() {
        assertThrows(IllegalArgumentException.class, () -> service.issue(null));
        assertThrows(IllegalArgumentException.class, () -> service.issue(" "));
    }
}
