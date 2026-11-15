package org.eudi.issuer_ips.service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.regex.Pattern;

/**
 * PKCE check for method S256 (RFC 7636, section 4.6):
 * BASE64URL(SHA-256(ASCII(code_verifier))) == code_challenge.
 */
public final class Pkce {

    /** RFC 7636, section 4.1: 43-128 characters from [A-Z a-z 0-9 - . _ ~]. */
    private static final Pattern VERIFIER = Pattern.compile("[A-Za-z0-9\\-._~]{43,128}");

    private Pkce() {
    }

    public static boolean verifyS256(String codeVerifier, String codeChallenge) {
        if (codeVerifier == null || codeChallenge == null || !VERIFIER.matcher(codeVerifier).matches()) {
            return false;
        }
        String expected = s256(codeVerifier);
        // constant-time comparison
        return MessageDigest.isEqual(
                expected.getBytes(StandardCharsets.US_ASCII),
                codeChallenge.getBytes(StandardCharsets.US_ASCII));
    }

    /** code_challenge for a code_verifier (also used in tests). */
    public static String s256(String codeVerifier) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256")
                    .digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
