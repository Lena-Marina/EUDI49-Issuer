package org.eudi.issuer_ips.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/**
 * Value of an entry in proof_types_supported (key e.g., "jwt").
 * Field name as in VC-K 5.10.1 CredentialRequestProofSupported
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CredentialRequestProofSupported {

    @JsonProperty("proof_signing_alg_values_supported")
    public List<String> proofSigningAlgValuesSupported;

    public List<String> getProofSigningAlgValuesSupported() {
        return proofSigningAlgValuesSupported;
    }

    public void setProofSigningAlgValuesSupported(List<String> proofSigningAlgValuesSupported) {
        this.proofSigningAlgValuesSupported = proofSigningAlgValuesSupported;
    }
}