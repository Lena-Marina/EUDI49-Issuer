package org.eudi.issuer_ips.controller;

import org.eudi.issuer_ips.config.IssuerUrlProperties;
import org.eudi.issuer_ips.model.OAuth2AuthorizationServerMetadata;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import java.util.List;

/**
 * Controller that provides the OAuth2 Authorization Server Metadata.
 * The Wallet automatically calls GET /.well-known/oauth-authorization-server
 * after it successfully fetches the credential issuer metadata.
 * Without this endpoint, the Wallet throws:
 * "Field 'issuer' is required for type OAuth2AuthorizationServerMetadata but it was missing"
 */

@RestController
@RequestMapping("/.well-known/")
public class OAuth2AuthorizationServerController {

    private final IssuerUrlProperties issuerUrls;

    public OAuth2AuthorizationServerController(IssuerUrlProperties issuerUrls) {
        this.issuerUrls = issuerUrls;
    }

    /**
     * Returns the OAuth2 Authorization Server Metadata as JSON.
     * This tells the Wallet:
     * - who the issuer is
     * - where to send the user for login (/authorize)
     * - where to exchange the authorization code for a token (/token)
     * - which OAuth2 flows are supported
     * - that PKCE with S256 is supported
     */

    @CrossOrigin
    @GetMapping(value = "/oauth-authorization-server", produces = "application/json")
    public OAuth2AuthorizationServerMetadata getAuthorizationServerMetadata() {
        OAuth2AuthorizationServerMetadata metadata = new OAuth2AuthorizationServerMetadata();
        metadata.setIssuer(issuerUrls.credentialIssuer());
        metadata.setAuthorizationEndpoint(issuerUrls.authorizationEndpoint());
        metadata.setTokenEndpoint(issuerUrls.tokenEndpoint());
        metadata.setResponseTypesSupported(List.of("code"));
        metadata.setGrantTypesSupported(List.of("authorization_code"));
        metadata.setCodeChallengeMethodsSupported(List.of("S256"));
        return metadata;
    }
}
