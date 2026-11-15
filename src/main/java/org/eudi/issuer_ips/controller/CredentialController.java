package org.eudi.issuer_ips.controller;

import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.JSONObjectUtils;
import org.eudi.issuer_ips.model.CredentialResponse;
import org.eudi.issuer_ips.model.OAuth2ErrorResponse;
import org.eudi.issuer_ips.service.AccessTokenService;
import org.eudi.issuer_ips.service.FhirSummaryException;
import org.eudi.issuer_ips.service.FhirSummaryService;
import org.eudi.issuer_ips.service.InvalidProofException;
import org.eudi.issuer_ips.service.JwtService;
import org.eudi.issuer_ips.service.PatientIdResolver;
import org.eudi.issuer_ips.service.ProofJwtValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.InvalidMediaTypeException;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import java.text.ParseException;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.eudi.issuer_ips.model.OAuth2ErrorResponse.*;

/**
 * Credential Endpoint (OpenID4VCI 1.0), in the format of VC-K 5.10.1.
 *
 * POST /credential
 *   Authorization: Bearer <access token from /token>
 *   Content-Type : application/json
 *   {"credential_identifier":"urn:eu.europa.ec.eudi:ips:1","proofs":{"jwt":["<proof JWT>"]}}
 *
 * Steps: access token -> user identifier -> request -> proof (holder key)
 *        -> patient ID (PatientIdResolver) -> IPS (FhirSummaryService) -> SD-JWT (JwtService)
 *
 * The body is read as text and parsed here, so that every error (also a wrong
 * Content-Type) gets a JSON answer {"error","error_description"}.
 */
@RestController
public class CredentialController {

    static final String IPS_CREDENTIAL_IDENTIFIER = TokenController.CREDENTIAL_CONFIGURATION_ID;

    private static final Logger log = LoggerFactory.getLogger(CredentialController.class);

    private final AccessTokenService accessTokenService;
    private final PatientIdResolver patientIdResolver;
    private final ProofJwtValidator proofJwtValidator;
    private final FhirSummaryService fhirSummaryService;
    private final JwtService jwtService;

    public CredentialController(AccessTokenService accessTokenService,
                                PatientIdResolver patientIdResolver,
                                ProofJwtValidator proofJwtValidator,
                                FhirSummaryService fhirSummaryService,
                                JwtService jwtService) {
        this.accessTokenService = accessTokenService;
        this.patientIdResolver = patientIdResolver;
        this.proofJwtValidator = proofJwtValidator;
        this.fhirSummaryService = fhirSummaryService;
        this.jwtService = jwtService;
    }

    @PostMapping("/credential")
    public ResponseEntity<?> credential(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization,
            @RequestHeader(value = HttpHeaders.CONTENT_TYPE, required = false) String contentType,
            @RequestBody(required = false) String body) {

        // --- 1. access token -> user identifier (401) ---------------------------
        Optional<String> userId = bearerToken(authorization).flatMap(accessTokenService::resolveUserId);
        if (userId.isEmpty()) {
            return unauthorized(authorization == null
                    ? "Authorization-Header mit Bearer-Token fehlt."
                    : "Access-Token ist ungültig oder abgelaufen.");
        }

        // --- 2. request: JSON, credential_identifier ----------------------------
        if (!isJson(contentType)) {
            return error(HttpStatus.BAD_REQUEST, INVALID_CREDENTIAL_REQUEST,
                    "Content-Type muss application/json sein (verschlüsselte Requests werden nicht unterstützt).");
        }
        Map<String, Object> request;
        try {
            request = JSONObjectUtils.parse(body == null ? "" : body);
        } catch (ParseException e) {
            return error(HttpStatus.BAD_REQUEST, INVALID_CREDENTIAL_REQUEST, "Body ist kein gültiges JSON-Objekt.");
        }

        Object identifier = request.get("credential_identifier");
        if (identifier == null) {
            return error(HttpStatus.BAD_REQUEST, INVALID_CREDENTIAL_REQUEST,
                    request.containsKey("credential_configuration_id")
                            ? "Die Token-Antwort enthält credential_identifiers: credential_identifier statt credential_configuration_id senden."
                            : "credential_identifier fehlt.");
        }
        if (request.containsKey("credential_configuration_id")) {
            return error(HttpStatus.BAD_REQUEST, INVALID_CREDENTIAL_REQUEST,
                    "credential_identifier und credential_configuration_id dürfen nicht gemeinsam vorkommen.");
        }
        if (!(identifier instanceof String id) || !IPS_CREDENTIAL_IDENTIFIER.equals(id)) {
            return error(HttpStatus.BAD_REQUEST, UNKNOWN_CREDENTIAL_IDENTIFIER,
                    "Unbekannter credential_identifier; unterstützt wird " + IPS_CREDENTIAL_IDENTIFIER + ".");
        }

        // --- 3. proof -> holder key ---------------------------------------------
        ECKey holderKey;
        try {
            holderKey = proofJwtValidator.validate(singleJwtProof(request));
        } catch (InvalidProofException e) {
            return error(HttpStatus.BAD_REQUEST, INVALID_PROOF, e.getMessage());
        }

        // --- 4. user identifier -> patient ID (no FHIR call if unknown) ---------
        Optional<String> patientId = patientIdResolver.resolvePatientId(userId.get());
        if (patientId.isEmpty()) {
            return error(HttpStatus.BAD_REQUEST, CREDENTIAL_REQUEST_DENIED,
                    "Für diese Nutzerkennung ist kein Patient hinterlegt.");
        }

        // --- 5. IPS from the FHIR server (502 on failure) -----------------------
        String fhirJson;
        try {
            fhirJson = fhirSummaryService.fetchSummaryJson(patientId.get());
        } catch (FhirSummaryException e) {
            log.warn("IPS-Abruf fehlgeschlagen ({}): {}", e.reason(), e.getMessage());
            return error(HttpStatus.BAD_GATEWAY, SERVER_ERROR, e.getMessage());
        }

        // --- 6. SD-JWT -------------------------------------------------------------
        String sdJwt;
        try {
            sdJwt = jwtService.createSdJwt(fhirJson, holderKey);
        } catch (Exception e) {
            log.error("SD-JWT konnte nicht erzeugt werden: {}", e.getClass().getSimpleName());
            return error(HttpStatus.INTERNAL_SERVER_ERROR, SERVER_ERROR, "Credential konnte nicht erzeugt werden.");
        }

        return ResponseEntity.ok()
                .headers(noStore())
                .contentType(MediaType.APPLICATION_JSON)
                .body(CredentialResponse.single(sdJwt));
    }

    // ------------------------------------------------------------------------

    /** "Bearer <token>" (scheme case-insensitive, RFC 6750 section 2.1); other schemes -> empty. */
    private static Optional<String> bearerToken(String authorization) {
        if (authorization == null || !authorization.regionMatches(true, 0, "Bearer ", 0, 7)) {
            return Optional.empty();
        }
        String token = authorization.substring(7).trim();
        return token.isEmpty() ? Optional.empty() : Optional.of(token);
    }

    private static boolean isJson(String contentType) {
        if (contentType == null) {
            return false;
        }
        try {
            MediaType type = MediaType.parseMediaType(contentType);
            return "application".equalsIgnoreCase(type.getType()) && "json".equalsIgnoreCase(type.getSubtype());
        } catch (InvalidMediaTypeException e) {
            return false;
        }
    }

    /**
     * proofs.jwt must be a list with exactly one string. Batch issuance is not announced
     * in the metadata; "proof" (singular, older drafts) is not supported.
     * OpenID4VCI 1.0: a missing or broken proofs parameter is invalid_proof.
     */
    private static String singleJwtProof(Map<String, Object> request) throws InvalidProofException {
        if (request.containsKey("proof")) {
            throw new InvalidProofException("proof (Einzahl) wird nicht unterstützt, proofs verwenden.");
        }
        if (!(request.get("proofs") instanceof Map<?, ?> proofs)) {
            throw new InvalidProofException("proofs fehlt oder ist kein Objekt.");
        }
        if (proofs.size() != 1 || !proofs.containsKey("jwt")) {
            throw new InvalidProofException("Nur der Proof-Typ jwt wird unterstützt.");
        }
        if (!(proofs.get("jwt") instanceof List<?> jwts) || jwts.isEmpty()) {
            throw new InvalidProofException("proofs.jwt muss eine Liste mit einem Proof-JWT sein.");
        }
        if (jwts.size() > 1) {
            throw new InvalidProofException("Genau ein Proof erwartet (keine Batch-Ausstellung).");
        }
        if (!(jwts.get(0) instanceof String jwt)) {
            throw new InvalidProofException("proofs.jwt[0] muss ein String sein.");
        }
        return jwt;
    }

    private static ResponseEntity<OAuth2ErrorResponse> unauthorized(String description) {
        HttpHeaders headers = noStore();
        headers.set(HttpHeaders.WWW_AUTHENTICATE, "Bearer error=\"" + INVALID_TOKEN + "\"");
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .headers(headers)
                .contentType(MediaType.APPLICATION_JSON)
                .body(new OAuth2ErrorResponse(INVALID_TOKEN, description));
    }

    private static ResponseEntity<OAuth2ErrorResponse> error(HttpStatus status, String error, String description) {
        return ResponseEntity.status(status)
                .headers(noStore())
                .contentType(MediaType.APPLICATION_JSON)
                .body(new OAuth2ErrorResponse(error, description));
    }

    /** The credential contains health data: never cache responses of this endpoint. */
    private static HttpHeaders noStore() {
        HttpHeaders headers = new HttpHeaders();
        headers.setCacheControl("no-store");
        headers.setPragma("no-cache");
        return headers;
    }
}
