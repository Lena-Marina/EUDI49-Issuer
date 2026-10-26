package org.eudi.issuer_ips.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;
import java.util.Map;

/**
 * Entry in credential_configurations_supported.
 * Field names as in VC-K 5.10.1 SupportedCredentialFormat
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class SupportedCredentialFormat {

    @JsonProperty("format")
    public String format;
    

    // relevant für SD-JWT ! //vct steht für "Verifiable Credential Type"
    @JsonProperty("vct")
    public String vct;

    @JsonProperty("cryptographic_binding_methods_supported")
    public List<String> cryptographicBindingMethodsSupported;

    @JsonProperty("credential_signing_alg_values_supported")
    public List<String> credentialSigningAlgValuesSupported;

    // Schlüssel: Proof-Typ (z. B. "jwt", OpenIdConstants.kt:124)
    @JsonProperty("proof_types_supported")
    public Map<String, CredentialRequestProofSupported> proofTypesSupported;

    // Getter & Setter
    public String getFormat() {
        return format;
    }

    public void setFormat(String format) {
        this.format = format;
    }

    public String getVct() {
        return vct;
    }

    public void setVct(String vct) {
        this.vct = vct;
    }

    public List<String> getCryptographicBindingMethodsSupported() {
        return cryptographicBindingMethodsSupported;
    }

    public void setCryptographicBindingMethodsSupported(List<String> cryptographicBindingMethodsSupported) {
        this.cryptographicBindingMethodsSupported = cryptographicBindingMethodsSupported;
    }

    public List<String> getCredentialSigningAlgValuesSupported() {
        return credentialSigningAlgValuesSupported;
    }

    public void setCredentialSigningAlgValuesSupported(List<String> credentialSigningAlgValuesSupported) {
        this.credentialSigningAlgValuesSupported = credentialSigningAlgValuesSupported;
    }

    public Map<String, CredentialRequestProofSupported> getProofTypesSupported() {
        return proofTypesSupported;
    }

    public void setProofTypesSupported(Map<String, CredentialRequestProofSupported> proofTypesSupported) {
        this.proofTypesSupported = proofTypesSupported;
    }
}