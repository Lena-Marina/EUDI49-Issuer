package org.eudi.issuer_ips;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONObjectUtils;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Builds key proofs (proofs.jwt) as VC-K 5.10.1 does (WalletService.createCredentialRequestProofJwt):
 *
 *   header : {"typ":"openid4vci-proof+jwt","alg":"ES256","jwk":{holder public key}}
 *   payload: {"iss":"https://wallet.a-sit.at/app","aud":<credential_issuer>,"iat":<seconds>}
 *
 * Header and payload are written by hand (not via Nimbus builders), so tests can
 * also build broken proofs (wrong typ, private jwk, missing claims ...).
 */
public final class ProofJwts {

    /** client_id of Valera, also iss of the proof. */
    public static final String WALLET_CLIENT_ID = "https://wallet.a-sit.at/app";

    private ProofJwts() {
    }

    /** New holder key pair (EC P-256), like the wallet key in Valera's keystore. */
    public static ECKey newKey() {
        return newKey(Curve.P_256);
    }

    public static ECKey newKey(Curve curve) {
        try {
            return new ECKeyGenerator(curve).generate();
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Valid proof for holderKey, aud = audience, issued at iat. Adjust with the builder methods. */
    public static Builder proof(ECKey holderKey, String audience, Instant iat) {
        return new Builder(holderKey, audience, iat);
    }

    public static final class Builder {

        private final Map<String, Object> header = new LinkedHashMap<>();
        private final Map<String, Object> payload = new LinkedHashMap<>();
        private ECKey signingKey;

        private Builder(ECKey holderKey, String audience, Instant iat) {
            header.put("typ", "openid4vci-proof+jwt");
            header.put("alg", "ES256");
            header.put("jwk", holderKey.toPublicJWK().toJSONObject());
            payload.put("iss", WALLET_CLIENT_ID);
            payload.put("aud", audience);
            payload.put("iat", iat.getEpochSecond());
            this.signingKey = holderKey;
        }

        /** Sets a header parameter; null removes it. */
        public Builder header(String name, Object value) {
            if (value == null) {
                header.remove(name);
            } else {
                header.put(name, value);
            }
            return this;
        }

        /** Sets a payload claim; null removes it. */
        public Builder claim(String name, Object value) {
            if (value == null) {
                payload.remove(name);
            } else {
                payload.put(name, value);
            }
            return this;
        }

        /** Signs with another key than the one in the header. */
        public Builder signWith(ECKey key) {
            this.signingKey = key;
            return this;
        }

        public String build() {
            String signingInput = Base64URL.encode(JSONObjectUtils.toJSONString(header)) + "."
                    + Base64URL.encode(JSONObjectUtils.toJSONString(payload));
            try {
                Base64URL signature = new ECDSASigner(signingKey)
                        .sign(new JWSHeader(JWSAlgorithm.ES256), signingInput.getBytes(StandardCharsets.US_ASCII));
                return signingInput + "." + signature;
            } catch (JOSEException e) {
                throw new IllegalStateException(e);
            }
        }
    }
}
