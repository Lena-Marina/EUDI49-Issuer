package org.eudi.issuer_ips.model;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;
import java.util.Map;

//ToDo: is this the correct way the Wallet expects IssuerMetadata to look like?
public class IssuerMetadata {

    @JsonProperty("credential_issuer")
    public String credentialIssuer;

    @JsonProperty("credential_endpoint")
    public String credentialEndpoint;

    @JsonProperty("authorization_servers")
    public List<String> authorizationServers;

    @JsonProperty("credential_configurations_supported")
    public Map<String, SupportedCredentialFormat> supportedCredentialConfigurations;

    public String getCredentialIssuer() {
        return credentialIssuer;
    }

    public void setCredentialIssuer(String credentialIssuer) {
        this.credentialIssuer = credentialIssuer;
    }

    public List<String> getAuthorizationServers() {
        return authorizationServers;
    }

    public void setAuthorizationServers(List<String> authorizationServers) {
        this.authorizationServers = authorizationServers;
    }

    public String getCredentialEndpoint() {
        return credentialEndpoint;
    }

    public void setCredentialEndpoint(String credentialEndpoint) {
        this.credentialEndpoint = credentialEndpoint;
    }

    public Map<String, SupportedCredentialFormat> getSupportedCredentialConfigurations() {
        return supportedCredentialConfigurations;
    }

    public void setSupportedCredentialConfigurations(
            Map<String, SupportedCredentialFormat> supportedCredentialConfigurations
    ) {
        this.supportedCredentialConfigurations = supportedCredentialConfigurations;
    }
}
