package org.eudi.issuer_ips.config;

import com.nimbusds.jwt.SignedJWT;
import org.eudi.issuer_ips.controller.OAuth2AuthorizationServerController;
import org.eudi.issuer_ips.model.IssuerMetadata;
import org.eudi.issuer_ips.model.OAuth2AuthorizationServerMetadata;
import org.eudi.issuer_ips.service.CredentialIdentifierService;
import org.eudi.issuer_ips.service.JwtService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * US11, AK 3: iss in the SD-JWT and credential_issuer in the metadata come from
 * the same property. The property is overridden here, so a hard-coded value
 * anywhere would make the test fail.
 */
@SpringBootTest(properties = "issuer.base-url=http://example.test:9999/")
class IssuerUrlConsistencyTest {

    private static final String EXPECTED = "http://example.test:9999";
    private static final String BUNDLE = """
            {"resourceType":"Bundle","type":"document","entry":[
              {"resource":{"resourceType":"Patient","id":"p1"}}]}""";

    @Autowired
    private JwtService jwtService;

    @Autowired
    private CredentialIdentifierService credentialIdentifierService;

    @Autowired
    private OAuth2AuthorizationServerController asController;

    @Test
    void issEqualsCredentialIssuer() throws Exception {
        String sdJwt = jwtService.createSdJwt("p1", BUNDLE);
        String iss = SignedJWT.parse(sdJwt.substring(0, sdJwt.indexOf('~'))).getJWTClaimsSet().getIssuer();

        IssuerMetadata metadata = credentialIdentifierService.getIssuerMetadata();

        assertEquals(EXPECTED, iss);
        assertEquals(EXPECTED, metadata.getCredentialIssuer());
        assertEquals(List.of(EXPECTED), metadata.getAuthorizationServers());
        assertEquals(EXPECTED + "/credential", metadata.getCredentialEndpoint());
    }

    @Test
    void authorizationServerMetadataUsesSameBaseUrl() {
        OAuth2AuthorizationServerMetadata as = asController.getAuthorizationServerMetadata();
        assertEquals(EXPECTED, as.getIssuer());
        assertEquals(EXPECTED + "/authorize", as.getAuthorizationEndpoint());
        assertEquals(EXPECTED + "/token", as.getTokenEndpoint());
    }
}
