package org.eudi.issuer_ips.service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.eudi.issuer_ips.config.IssuerProperties;
import org.eudi.issuer_ips.config.IssuerUrlProperties;
import org.springframework.stereotype.Service;

import java.text.ParseException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;

/**
 * Checks the key proof (proofs.jwt[0]) of a credential request, as VC-K 5.10.1 builds it
 * (WalletService.createCredentialRequestProofJwt):
 *
 *   header : typ openid4vci-proof+jwt, alg ES256, jwk (holder public key, EC P-256)
 *   payload: iss = client_id, aud = credential_issuer, iat; NO nonce
 *
 * No nonce. Replacement protection: aud, iss and iat (at most 5 minutes old).
 * A small clock skew into the future is tolerated, because wallet and issuer clocks differ.
 *
 * Result: the holder public key, to be bound into the credential (cnf.jwk).
 */
@Service
public class ProofJwtValidator {

    public static final JOSEObjectType PROOF_TYPE = new JOSEObjectType("openid4vci-proof+jwt");

    /** iat may be at most this old */
    public static final Duration MAX_AGE = Duration.ofMinutes(5);

    /** iat may be at most this far in the future (clock skew between phone and issuer). */
    public static final Duration MAX_CLOCK_SKEW = Duration.ofSeconds(60);

    private final Clock clock;
    private final String expectedAudience;
    private final String expectedIssuer;

    public ProofJwtValidator(Clock clock, IssuerUrlProperties issuerUrls, IssuerProperties issuerProperties) {
        this.clock = clock;
        this.expectedAudience = issuerUrls.credentialIssuer();
        this.expectedIssuer = issuerProperties.walletClient().clientId();
    }

    /**
     * @return the holder public key from the proof header (never contains "d")
     * @throws InvalidProofException
     */
    public ECKey validate(String proofJwt) throws InvalidProofException {
        if (proofJwt == null || proofJwt.isBlank()) {
            throw new InvalidProofException("Proof-JWT ist leer.");
        }

        SignedJWT jwt;
        try {
            jwt = SignedJWT.parse(proofJwt);
        } catch (ParseException | IllegalArgumentException e) {
            throw new InvalidProofException("Proof ist kein gültiges signiertes JWT.");
        }

        // --- header ----------------------------------------------------------
        JWSHeader header = jwt.getHeader();
        if (!PROOF_TYPE.equals(header.getType())) {
            throw new InvalidProofException("typ im Proof-Header muss openid4vci-proof+jwt sein.");
        }
        if (!JWSAlgorithm.ES256.equals(header.getAlgorithm())) {
            throw new InvalidProofException("alg im Proof-Header muss ES256 sein.");
        }
        JWK jwk = header.getJWK();
        if (jwk == null) {
            throw new InvalidProofException("jwk im Proof-Header fehlt.");
        }
        if (!(jwk instanceof ECKey ecKey) || !Curve.P_256.equals(ecKey.getCurve())) {
            throw new InvalidProofException("jwk im Proof-Header muss ein EC-Schlüssel auf P-256 sein.");
        }
        if (ecKey.isPrivate()) {
            throw new InvalidProofException("jwk im Proof-Header darf keinen privaten Schlüssel enthalten.");
        }

        // --- signature with the header key -----------------------------------
        try {
            if (!jwt.verify(new ECDSAVerifier(ecKey))) {
                throw new InvalidProofException("Signatur des Proofs passt nicht zum jwk im Header.");
            }
        } catch (JOSEException e) {
            throw new InvalidProofException("Signatur des Proofs konnte nicht geprüft werden.");
        }

        // --- payload -----------------------------------------------------------
        JWTClaimsSet claims;
        try {
            claims = jwt.getJWTClaimsSet();
        } catch (ParseException e) {
            throw new InvalidProofException("Payload des Proofs ist kein gültiges JSON.");
        }

        List<String> audience = claims.getAudience();
        if (audience == null || !audience.contains(expectedAudience)) {
            throw new InvalidProofException("aud muss " + expectedAudience + " sein.");
        }
        if (!expectedIssuer.equals(claims.getIssuer())) {
            throw new InvalidProofException("iss muss die client_id der Wallet sein.");
        }

        Date iatDate = claims.getIssueTime();
        if (iatDate == null) {
            throw new InvalidProofException("iat fehlt.");
        }
        Instant iat = iatDate.toInstant();
        Instant now = clock.instant();
        if (iat.isAfter(now.plus(MAX_CLOCK_SKEW))) {
            throw new InvalidProofException("iat liegt in der Zukunft.");
        }
        if (iat.isBefore(now.minus(MAX_AGE))) {
            throw new InvalidProofException("Proof ist älter als 5 Minuten.");
        }

        return ecKey.toPublicJWK();
    }
}
