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
        // Wallet expects a map with all SupportedCredentialFormats -> We only have one: the Ips
        Map<String, SupportedCredentialFormat> configs = new HashMap<>();


        //Creating the SupportedCredentialFormat -> Testing one the Wallet knows
        SupportedCredentialFormat atomicAttribute = new SupportedCredentialFormat();
        atomicAttribute.setFormat("vc+sd-jwt");
        atomicAttribute.setVct("AtomicAttribute2023"); //ips.setVct("eu.europa.ec.eudi.ips"); //Todo: in der Wallet eine für den IPS registrieren?

        //Creating the SupportedCredentialFormat -> Testing one the Wallet knows
        SupportedCredentialFormat ips = new SupportedCredentialFormat();
        ips.setFormat("vc+sd-jwt");
        ips.setVct("ips"); //this is not something the Wallet knows yet!!!!

        //Adding the SupportedCredentialFormats to the Map
        configs.put("AtomicAttribute", atomicAttribute);
        configs.put("ips", ips);



        //Creating Issuer Metadata Todo: at the moment everything in there is just mocking (currently trying to get SupportedCredentialConfigurations right)
        IssuerMetadata metadata = new IssuerMetadata();
        metadata.setCredentialIssuer("http://10.0.2.2:8080"); //this is us
        metadata.setAuthorizationServers(List.of("http://10.0.2.2:8080")); // this is currently us, but we want to know if we can use the existing Wallet-Issuer?
        metadata.setCredentialEndpoint("http://10.0.2.2:8080/credential"); //this is us
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

        SupportedCredentialFormat ips = new SupportedCredentialFormat();
        ips.setFormat("dc+sd-jwt");
        ips.setVct("urn:eu.europa.ec.eudi:ips:1"); //Muss genau mit sdJwtType: String in IpsScheme im IpsScheme-Package übereinstimmen!


        configs.put("urn:eu.europa.ec.eudi:ips:1", ips);

        IssuerMetadata metadata = new IssuerMetadata();
        metadata.setCredentialIssuer("http://10.0.2.2:8080"); //this is our issuer (local Host)
        metadata.setAuthorizationServers(List.of("http://10.0.2.2:8080")); //this is our issuer (local Host) BUT we want to know of we can the AuthServer the already implemented Credentials use
        metadata.setCredentialEndpoint("http://10.0.2.2:8080/credential"); //this is our issuer (local Host) ToDo: Endpoint not implemented
        metadata.setSupportedCredentialConfigurations(configs);

        return metadata;
    }
}