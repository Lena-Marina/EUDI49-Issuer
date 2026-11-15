package org.eudi.issuer_ips.controller;

import ca.uhn.fhir.context.FhirContext;
import ca.uhn.fhir.rest.client.api.IGenericClient;
import com.nimbusds.jwt.SignedJWT;
import org.eudi.issuer_ips.service.JwtService;
import org.hl7.fhir.instance.model.api.IBaseResource;
import org.hl7.fhir.r4.model.Bundle;
import org.hl7.fhir.r4.model.IdType;
import org.hl7.fhir.r4.model.Parameters;
import org.hl7.fhir.r4.model.Patient;
import org.springframework.web.bind.annotation.*;

// Controller for PatientSummary related stuff
// The FHIR server is configured via issuer.fhir.base-url (application.properties)

@RestController
@RequestMapping("/issuer")
public class PatientSummaryController {

    private final FhirContext fhirContext;
    private final IGenericClient fhirClient;
    private final JwtService jwtService;

    public PatientSummaryController(FhirContext fhirContext, IGenericClient fhirClient, JwtService jwtService) {
        this.fhirContext = fhirContext;
        this.fhirClient = fhirClient;
        this.jwtService = jwtService;
    }

    //Gets a bundle of multiple Patients
    @GetMapping("/Patient")
    public Bundle getPatients() {
        return fhirClient.search().forResource(Patient.class).returnBundle(Bundle.class).execute();
    }

    // Gets summary from a specific patient
    @GetMapping(value = "/Patient/{id}/$summary", produces = "application/fhir+json")
    public String getPatientSummary(@PathVariable String id) {
        Bundle bundle = fhirClient.operation().onInstance(new IdType("Patient", id)).named("$summary")
                .withNoParameters(Parameters.class).useHttpGet().returnResourceType(Bundle.class).execute();

        return fhirContext.newJsonParser().setPrettyPrint(true).encodeResourceToString(bundle);
    }

    // Creates simple jwt from summary, uses patient id
    @GetMapping(value = "/Patient/{id}/jwt" )
    public String getPatientJwt(@PathVariable String id) throws Exception {
        IBaseResource result = fhirClient.operation()
                .onInstance(new IdType("Patient", id))
                .named("$summary")
                .withNoParameters(Parameters.class)
                .useHttpGet()
                .execute();

        String fhirJson = fhirContext.newJsonParser()
                .encodeResourceToString(result);

        return jwtService.createJwt(id, fhirJson);
    }

    // creates sd-jwt from summary, uses patient id
    @GetMapping(value = "/Patient/{id}/sdjwt")
    public String getPatientSdJwt(@PathVariable String id) throws Exception {
        Bundle bundle = fhirClient.operation()
                .onInstance(new IdType("Patient", id))
                .named("$summary")
                .withNoParameters(Parameters.class)
                .useHttpGet()
                .returnResourceType(Bundle.class)  // without this, $summary is not parsed as Bundle
                .execute();

        String fhirJson = fhirContext.newJsonParser()
                .encodeResourceToString(bundle);

        return jwtService.createSdJwt(id, fhirJson);
    }

    // ONLY FOR TEST ENVIRONMENTS
    // can be used to decode jwt & sd-jwt
    @PostMapping("/decode")
    public Object decode(@RequestBody String token) throws Exception {
        SignedJWT jwt = SignedJWT.parse(token);
        return jwt.getJWTClaimsSet().toJSONObject();
    }
}
