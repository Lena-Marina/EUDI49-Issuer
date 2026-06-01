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
// PatientId that can be used: 90293390

@RestController
@RequestMapping("/issuer")
public class PatientSummaryController {

    private final FhirContext fhirContext;

    private final JwtService jwtService;
    public PatientSummaryController(FhirContext fhirContext, JwtService jwtService) {
        this.fhirContext = fhirContext;
        this.jwtService = jwtService;
    }

    //Gets a bundle of multiple Patients
    @GetMapping("/Patient")
    public Bundle getPatients() {

        IGenericClient client = fhirContext.newRestfulGenericClient("https://hapi.fhir.org/baseR4");

        return client.search().forResource(Patient.class).returnBundle(Bundle.class).execute();
    }

    // Gets summary from a specific patient
    @GetMapping(value = "/Patient/{id}/$summary", produces = "application/fhir+json")
    public String getPatientSummary(@PathVariable String id) {

        IGenericClient client = fhirContext.newRestfulGenericClient("https://hapi.fhir.org/baseR4");

        Bundle bundle = client.operation().onInstance(new IdType("Patient", id)).named("$summary")
                .withNoParameters(Parameters.class).useHttpGet().returnResourceType(Bundle.class).execute();

        return fhirContext.newJsonParser().setPrettyPrint(true).encodeResourceToString(bundle);
    }

    // Creates simple jwt from summary, uses patient id
    @GetMapping(value = "/Patient/{id}/jwt" )
    public String getPatientJwt(@PathVariable String id) throws Exception {
        IGenericClient client = fhirContext.newRestfulGenericClient("https://hapi.fhir.org/baseR4");
        IBaseResource result = client.operation()
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
    @GetMapping(value = "/Patient/{id}/sdjwt" )
    public String getPatientSdJwt(@PathVariable String id) throws Exception {
        IGenericClient client = fhirContext.newRestfulGenericClient("https://hapi.fhir.org/baseR4");
        IBaseResource result = client.operation()
                .onInstance(new IdType("Patient", id))
                .named("$summary")
                .withNoParameters(Parameters.class)
                .useHttpGet()
                .execute();

        String fhirJson = fhirContext.newJsonParser()
                .encodeResourceToString(result);

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
