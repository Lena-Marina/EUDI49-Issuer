package org.eudi.issuer_ips.service;

import ca.uhn.fhir.context.FhirContext;
import ca.uhn.fhir.parser.DataFormatException;
import ca.uhn.fhir.rest.client.api.IGenericClient;
import ca.uhn.fhir.rest.client.exceptions.FhirClientConnectionException;
import ca.uhn.fhir.rest.server.exceptions.BaseServerResponseException;
import ca.uhn.fhir.rest.server.exceptions.ResourceNotFoundException;
import org.hl7.fhir.r4.model.Bundle;
import org.hl7.fhir.r4.model.IdType;
import org.hl7.fhir.r4.model.Parameters;
import org.hl7.fhir.r4.model.Patient;
import org.springframework.stereotype.Service;

/**
 * The only place that talks to the FHIR server (issuer.fhir.base-url, client from FhirConfig).
 * Used by /credential and by the test endpoints in PatientSummaryController.
 */
@Service
public class FhirSummaryService {

    private final IGenericClient fhirClient;
    private final FhirContext fhirContext;

    public FhirSummaryService(IGenericClient fhirClient, FhirContext fhirContext) {
        this.fhirClient = fhirClient;
        this.fhirContext = fhirContext;
    }

    /**
     * GET Patient/{id}/$summary as Bundle.
     *
     * @throws FhirSummaryException PATIENT_NOT_FOUND (404) or SERVER_UNAVAILABLE (anything else)
     */
    public Bundle fetchSummary(String patientId) {
        try {
            return fhirClient.operation()
                    .onInstance(new IdType("Patient", patientId))
                    .named("$summary")
                    .withNoParameters(Parameters.class)
                    .useHttpGet()
                    .returnResourceType(Bundle.class)   // without this, $summary is not parsed as Bundle
                    .execute();
        } catch (ResourceNotFoundException e) {
            throw new FhirSummaryException(FhirSummaryException.Reason.PATIENT_NOT_FOUND,
                    "Der FHIR-Server kennt den Patienten nicht.", e);
        } catch (FhirClientConnectionException e) {
            throw new FhirSummaryException(FhirSummaryException.Reason.SERVER_UNAVAILABLE,
                    "Der FHIR-Server ist nicht erreichbar.", e);
        } catch (BaseServerResponseException e) {
            throw new FhirSummaryException(FhirSummaryException.Reason.SERVER_UNAVAILABLE,
                    "Der FHIR-Server hat mit HTTP " + e.getStatusCode() + " geantwortet.", e);
        } catch (DataFormatException e) {
            throw new FhirSummaryException(FhirSummaryException.Reason.SERVER_UNAVAILABLE,
                    "Die Antwort des FHIR-Servers ist kein gültiges Bundle.", e);
        }
    }

    /** $summary as compact FHIR JSON (input for JwtService). */
    public String fetchSummaryJson(String patientId) {
        return fhirContext.newJsonParser().encodeResourceToString(fetchSummary(patientId));
    }

    /** $summary as pretty-printed FHIR JSON (test endpoint /issuer/Patient/{id}/$summary). */
    public String fetchSummaryJsonPretty(String patientId) {
        return fhirContext.newJsonParser().setPrettyPrint(true).encodeResourceToString(fetchSummary(patientId));
    }

    /** Search for patients (test endpoint /issuer/Patient). */
    public Bundle searchPatients() {
        return fhirClient.search().forResource(Patient.class).returnBundle(Bundle.class).execute();
    }
}
