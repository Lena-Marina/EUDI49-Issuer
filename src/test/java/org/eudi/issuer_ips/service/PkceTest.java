package org.eudi.issuer_ips.service;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class PkceTest {

    /** Example from RFC 7636, Appendix B. */
    private static final String RFC_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private static final String RFC_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    @Test
    void rfcExampleVerifies() {
        assertEquals(RFC_CHALLENGE, Pkce.s256(RFC_VERIFIER));
        assertTrue(Pkce.verifyS256(RFC_VERIFIER, RFC_CHALLENGE));
    }

    @Test
    void wrongVerifierFails() {
        assertFalse(Pkce.verifyS256(RFC_VERIFIER.replace('d', 'e'), RFC_CHALLENGE));
    }

    @Test
    void plainMethodValueIsNotAccepted() {
        // verifier == challenge would be "plain", must fail for S256
        assertFalse(Pkce.verifyS256(RFC_CHALLENGE, RFC_CHALLENGE));
    }

    @Test
    void malformedVerifierFails() {
        assertFalse(Pkce.verifyS256("zu-kurz", Pkce.s256("zu-kurz")));
        assertFalse(Pkce.verifyS256(null, RFC_CHALLENGE));
        assertFalse(Pkce.verifyS256(RFC_VERIFIER, null));
    }
}
