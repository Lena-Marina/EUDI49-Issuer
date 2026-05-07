package org.eudi.issuer_ips.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

/**
 * Model class representing the OAuth2 Authorization Server Metadata.
 * This is returned by the /.well-known/oauth-authorization-server endpoint.
 * The Wallet automatically calls this endpoint after the credential issuer metadata endpoint.
 * The field names (via @JsonProperty) must match exactly what the Wallet expects,
 * as defined in the OID4VCI standard.
 */

public class OAuth2AuthorizationServerMetadata {

    @JsonProperty("issuer")
    public String issuer;

    @JsonProperty("authorization_endpoint")
    public String authorizationEndpoint;

    @JsonProperty("token_endpoint")
    public String tokenEndpoint;

    @JsonProperty("response_types_supported")
    public List<String> responseTypesSupported;

    @JsonProperty("grant_types_supported")
    public List<String> grantTypesSupported;

    // Getters and Setters
    public String getIssuer() { return issuer; }
    public void setIssuer(String issuer) { this.issuer = issuer; }

    public String getAuthorizationEndpoint() { return authorizationEndpoint; }
    public void setAuthorizationEndpoint(String authorizationEndpoint) { this.authorizationEndpoint = authorizationEndpoint; }

    public String getTokenEndpoint() { return tokenEndpoint; }
    public void setTokenEndpoint(String tokenEndpoint) { this.tokenEndpoint = tokenEndpoint; }

    public List<String> getResponseTypesSupported() { return responseTypesSupported; }
    public void setResponseTypesSupported(List<String> responseTypesSupported) { this.responseTypesSupported = responseTypesSupported; }

    public List<String> getGrantTypesSupported() { return grantTypesSupported; }
    public void setGrantTypesSupported(List<String> grantTypesSupported) { this.grantTypesSupported = grantTypesSupported; }
}
