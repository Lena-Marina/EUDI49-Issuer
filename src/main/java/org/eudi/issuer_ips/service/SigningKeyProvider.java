package org.eudi.issuer_ips.service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * Issuer signing key (EC P-256, for ES256).
 *
 * The key is generated in memory at every start.
 * It is never written to a file, to the configuration or to the log.
 * This is sufficient because Valera takes the issuer key from the "jwk"
 * header of the SD-JWT (no trust list). A productive issuer would need a
 * persistent key with a certificate; only this class would have to change.
 */
@Component
public class SigningKeyProvider {

    private static final Logger log = LoggerFactory.getLogger(SigningKeyProvider.class);

    private final ECKey key;
    private final ECKey publicJwk;

    @Autowired
    public SigningKeyProvider() {
        this(generate());
    }

    /** For tests: use a given key. */
    SigningKeyProvider(ECKey key) {
        if (!Curve.P_256.equals(key.getCurve()) || !key.isPrivate()) {
            throw new IllegalArgumentException("Erwartet wird ein privater EC-Schlüssel auf P-256");
        }
        this.key = key;
        // only kty, crv, x, y - no d, no kid, no use, no alg
        this.publicJwk = new ECKey.Builder(Curve.P_256, key.getX(), key.getY()).build();
        log.info("Signaturschlüssel (ES256, flüchtig) bereit, JWK-Thumbprint (SHA-256): {}", thumbprint());
    }

    /** Public key as JWK, to be put into the JWS header. Never contains "d". */
    public ECKey publicJwk() {
        return publicJwk;
    }

    /** Signer for ES256. Nimbus produces the JOSE signature format R||S (64 bytes). */
    public JWSSigner signer() {
        try {
            return new ECDSASigner(key);
        } catch (JOSEException e) {
            throw new IllegalStateException("ES256-Signer konnte nicht erzeugt werden", e);
        }
    }

    /** RFC 7638 thumbprint of the public key, safe to log. */
    public String thumbprint() {
        try {
            return publicJwk.computeThumbprint().toString();
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    private static ECKey generate() {
        try {
            return new ECKeyGenerator(Curve.P_256).generate();
        } catch (JOSEException e) {
            throw new IllegalStateException("EC-Schlüssel konnte nicht erzeugt werden", e);
        }
    }
}
