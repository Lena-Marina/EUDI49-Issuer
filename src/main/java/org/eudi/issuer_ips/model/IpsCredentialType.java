package org.eudi.issuer_ips.model;

/**
 * The one credential type of this issuer.
 *
 * VCT is used for "vct" in the metadata (CredentialIdentifierService) AND in every
 * issued SD-JWT (JwtService), so both can never differ. It must match sdJwtType of
 * IpsScheme (Valera, IpsScheme repository): Valera maps a stored credential to its
 * scheme via this value.
 */
public final class IpsCredentialType {

    public static final String VCT = "urn:eu.europa.ec.eudi:ips:1";

    private IpsCredentialType() {
    }
}
