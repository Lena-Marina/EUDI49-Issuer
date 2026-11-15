package org.eudi.issuer_ips.service;

/**
 * The key proof (proofs.jwt) of a credential request is invalid.
 * The message goes into error_description of the invalid_proof response.
 */
public class InvalidProofException extends Exception {

    public InvalidProofException(String message) {
        super(message);
    }
}
