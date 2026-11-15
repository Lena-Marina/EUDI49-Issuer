package org.eudi.issuer_ips.service;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;
import org.eudi.issuer_ips.MutableClock;
import org.eudi.issuer_ips.ProofJwts;
import org.eudi.issuer_ips.config.IssuerProperties;
import org.eudi.issuer_ips.config.IssuerUrlProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Proof JWT as VC-K 5.10.1 sends it, without nonce
 * typ openid4vci-proof+jwt, signature valid with the header jwk, aud = credential_issuer,
 * iss = client_id, iat at most 5 minutes old. Pure JUnit, controllable clock.
 */
class ProofJwtValidatorTest {

    static final String ISSUER = "http://issuer.test:8080";
    static final Instant NOW = Instant.parse("2026-11-16T10:00:00Z");

    private static final ECKey HOLDER = ProofJwts.newKey();
    private static final ECKey OTHER = ProofJwts.newKey();
    private static final ECKey P384 = ProofJwts.newKey(Curve.P_384);

    private ProofJwtValidator validator;

    @BeforeEach
    void setUp() {
        IssuerProperties props = new IssuerProperties(
                new IssuerProperties.WalletClient(ProofJwts.WALLET_CLIENT_ID, "asitplus-wallet://cb"), null, null);
        validator = new ProofJwtValidator(new MutableClock(NOW), new IssuerUrlProperties(ISSUER), props);
    }

    private static ProofJwts.Builder valid() {
        return ProofJwts.proof(HOLDER, ISSUER, NOW);
    }

    // ---- accepted ----------------------------------------------------------

    /** Proof exactly like VC-K builds it (no nonce) -> holder public key, without d. */
    @Test
    void validProofWithoutNonceReturnsHolderPublicKey() throws Exception {
        ECKey holderKey = validator.validate(valid().build());

        assertEquals(HOLDER.toPublicJWK().toJSONObject(), holderKey.toJSONObject());
        assertFalse(holderKey.isPrivate(), "Holder-Schlüssel darf kein d enthalten");
    }

    /** aud may also be an array (RFC 7519), as long as it contains credential_issuer. */
    @Test
    void audienceArrayContainingIssuerIsAccepted() {
        assertDoesNotThrow(() -> validator.validate(valid().claim("aud", List.of(ISSUER, "https://other.test")).build()));
    }

    /** "höchstens 5 Min. alt": exactly 5 minutes is still accepted. */
    @Test
    void proofExactlyFiveMinutesOldIsAccepted() {
        assertDoesNotThrow(() -> validator.validate(
                ProofJwts.proof(HOLDER, ISSUER, NOW.minus(ProofJwtValidator.MAX_AGE)).build()));
    }

    /** Phone clock slightly ahead (up to 60 s) is tolerated. */
    @Test
    void smallClockSkewIntoTheFutureIsAccepted() {
        assertDoesNotThrow(() -> validator.validate(
                ProofJwts.proof(HOLDER, ISSUER, NOW.plus(ProofJwtValidator.MAX_CLOCK_SKEW)).build()));
    }

    // ---- rejected ----------------------------------------------------------

    enum BrokenProof {
        NOT_A_JWT {
            String build() { return "kein.jwt"; }
        },
        WRONG_TYP {
            String build() { return valid().header("typ", "JWT").build(); }
        },
        MISSING_TYP {
            String build() { return valid().header("typ", null).build(); }
        },
        WRONG_ALG {
            String build() { return valid().header("alg", "ES384").build(); }
        },
        MISSING_JWK_ONLY_KID {
            String build() { return valid().header("jwk", null).header("kid", "holder-1").build(); }
        },
        JWK_ON_OTHER_CURVE {
            String build() { return valid().header("jwk", P384.toPublicJWK().toJSONObject()).build(); }
        },
        PRIVATE_JWK_IN_HEADER {
            String build() { return valid().header("jwk", HOLDER.toJSONObject()).build(); }
        },
        SIGNED_WITH_OTHER_KEY {
            String build() { return valid().signWith(OTHER).build(); }
        },
        PAYLOAD_CHANGED_AFTER_SIGNING {
            String build() {
                String[] parts = valid().build().split("\\.");
                String otherPayload = valid().claim("iss", "https://attacker.test").build().split("\\.")[1];
                return parts[0] + "." + otherPayload + "." + parts[2];
            }
        },
        WRONG_AUD {
            String build() { return valid().claim("aud", "https://other-issuer.test").build(); }
        },
        MISSING_AUD {
            String build() { return valid().claim("aud", null).build(); }
        },
        WRONG_ISS {
            String build() { return valid().claim("iss", "https://other-wallet.test").build(); }
        },
        MISSING_ISS {
            String build() { return valid().claim("iss", null).build(); }
        },
        MISSING_IAT {
            String build() { return valid().claim("iat", null).build(); }
        },
        IAT_OLDER_THAN_FIVE_MINUTES {
            String build() {
                return ProofJwts.proof(HOLDER, ISSUER, NOW.minus(ProofJwtValidator.MAX_AGE).minusSeconds(1)).build();
            }
        },
        IAT_TOO_FAR_IN_THE_FUTURE {
            String build() {
                return ProofJwts.proof(HOLDER, ISSUER, NOW.plus(ProofJwtValidator.MAX_CLOCK_SKEW).plusSeconds(1)).build();
            }
        };

        abstract String build();
    }

    @ParameterizedTest
    @EnumSource(BrokenProof.class)
    void brokenProofIsRejected(BrokenProof broken) {
        String proof = broken.build();
        InvalidProofException e = assertThrows(InvalidProofException.class, () -> validator.validate(proof),
                broken + " wurde akzeptiert");
        assertNotNull(e.getMessage());
        assertFalse(e.getMessage().isBlank(), "Begründung für error_description fehlt");
    }

    /** Sanity check of the helper: the manipulated payload really is a different payload. */
    @Test
    void manipulatedPayloadDiffersFromSignedOne() {
        String original = valid().build().split("\\.")[1];
        String changed = BrokenProof.PAYLOAD_CHANGED_AFTER_SIGNING.build().split("\\.")[1];
        assertNotEquals(original, changed);
        assertTrue(new Base64URL(changed).decodeToString().contains("attacker"));
    }
}
