package org.eudi.issuer_ips.controller;

import org.eudi.issuer_ips.model.IssuerMetadata;
import org.eudi.issuer_ips.service.CredentialIdentifierService;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/*
* In the Valera Project the following Endpoint is called from:
* {credentialIssuer}/.well-known/openid-credential-issuer
* As can be seen in OpenId4VciClient
* {credentialIssuer} == our base path (on Emulator: http://10.0.2.2:8080)
*
* We are not returning a List, but a Single Object that contains a MAP!
* */

@RestController
@RequestMapping("/.well-known/")
public class CredentialIdentifierController {

    private CredentialIdentifierService credIdService;

    public CredentialIdentifierController(CredentialIdentifierService credentialIdentifierService) {
        this.credIdService = credentialIdentifierService;
    }

    @CrossOrigin
    @GetMapping(value = "/openid-credential-issuer", produces = "application/json") //ToDo: does the wallet expect "application/json"?
    public IssuerMetadata getIssuerMetadata() {
        //log to see if called?
        return credIdService.getIssuerMetadata();
    }
}
