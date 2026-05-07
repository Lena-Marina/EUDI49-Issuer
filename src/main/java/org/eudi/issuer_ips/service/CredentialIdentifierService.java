/*package org.eudi.issuer_ips.service;

import org.eudi.issuer_ips.model.IssuerMetadata;
import org.eudi.issuer_ips.model.SupportedCredentialFormat;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
public class CredentialIdentifierService {

    public IssuerMetadata getIssuerMetadata() {
        Map<String, SupportedCredentialFormat> configs = new HashMap<>();

        SupportedCredentialFormat pid = new SupportedCredentialFormat();
        pid.setFormat("mso_mdoc");

        SupportedCredentialFormat ips = new SupportedCredentialFormat();
        ips.setFormat("jwt_vc_json");

        configs.put("PID", pid);

        IssuerMetadata metadata = new IssuerMetadata();
        metadata.setCredentialIssuer("https://issuer.example.com");
        metadata.setAuthorizationServers(List.of("https://issuer.example.com")); //Where we will do the authentififcation, maybe we can use the existing Wallet-Issuer?
        metadata.setCredentialEndpoint("https://issuer.example.com/credential"); //where we will get the Credential from (this issuer)
        metadata.setSupportedCredentialConfigurations(configs);

        return metadata;
    }
}*/
package org.eudi.issuer_ips.service;

import org.eudi.issuer_ips.model.IssuerMetadata;
import org.eudi.issuer_ips.model.SupportedCredentialFormat;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
public class CredentialIdentifierService {

    public IssuerMetadata getIssuerMetadata() {
        Map<String, SupportedCredentialFormat> configs = new HashMap<>();

        SupportedCredentialFormat pid = new SupportedCredentialFormat();
        pid.setFormat("mso_mdoc");
        pid.setDocType("eu.europa.ec.eudi.pid.1");

        configs.put("PID", pid);

        IssuerMetadata metadata = new IssuerMetadata();
        metadata.setCredentialIssuer("http://10.0.2.2:8080");
        metadata.setAuthorizationServers(List.of("http://10.0.2.2:8080"));
        metadata.setCredentialEndpoint("http://10.0.2.2:8080/credential");
        metadata.setSupportedCredentialConfigurations(configs);

        return metadata;
    }
}