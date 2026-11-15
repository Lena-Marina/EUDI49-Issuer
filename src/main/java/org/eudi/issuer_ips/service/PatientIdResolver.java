package org.eudi.issuer_ips.service;

import java.util.Optional;

/**
 * "User identifier -> patient ID".
 * Now: ConfigPatientIdResolver (table in application.properties).
 * Later e.g. a lookup in a patient index for ID Austria users.
 *
 * Called only in /credential: the access token knows the user identifier, never the patient ID.
 */
@FunctionalInterface
public interface PatientIdResolver {

    /**
     * @return the patient ID on the FHIR server, or Optional.empty() if the user has none
     */
    Optional<String> resolvePatientId(String userId);
}
