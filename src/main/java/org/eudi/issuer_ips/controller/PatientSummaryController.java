package org.eudi.issuer_ips.controller;

import com.nimbusds.jwt.SignedJWT;
import org.eudi.issuer_ips.service.FhirSummaryService;
import org.eudi.issuer_ips.service.JwtService;
import org.hl7.fhir.r4.model.Bundle;
import org.springframework.web.bind.annotation.*;

// Test endpoints for the patient summary.
// FHIR access lives in FhirSummaryService (server: issuer.fhir.base-url).

@RestController
@RequestMapping("/issuer")
public class PatientSummaryController {

    private final FhirSummaryService fhirSummaryService;
    private final JwtService jwtService;

    public PatientSummaryController(FhirSummaryService fhirSummaryService, JwtService jwtService) {
        this.fhirSummaryService = fhirSummaryService;
        this.jwtService = jwtService;
    }

    //Gets a bundle of multiple Patients
    @GetMapping("/Patient")
    public Bundle getPatients() {
        return fhirSummaryService.searchPatients();
    }

    // Gets summary from a specific patient
    @GetMapping(value = "/Patient/{id}/$summary", produces = "application/fhir+json")
    public String getPatientSummary(@PathVariable String id) {
        return fhirSummaryService.fetchSummaryJsonPretty(id);
    }

    // Creates simple jwt from summary, uses patient id
    @GetMapping(value = "/Patient/{id}/jwt")
    public String getPatientJwt(@PathVariable String id) throws Exception {
        return jwtService.createJwt(id, fhirSummaryService.fetchSummaryJson(id));
    }

    // creates sd-jwt from summary (same method as /credential, without holder key and without sub)
    @GetMapping(value = "/Patient/{id}/sdjwt")
    public String getPatientSdJwt(@PathVariable String id) throws Exception {
        return jwtService.createSdJwt(fhirSummaryService.fetchSummaryJson(id), null);
    }

    // ONLY FOR TEST ENVIRONMENTS
    // can be used to decode jwt & sd-jwt
    @PostMapping("/decode")
    public Object decode(@RequestBody String token) throws Exception {
        SignedJWT jwt = SignedJWT.parse(token);
        return jwt.getJWTClaimsSet().toJSONObject();
    }
}
