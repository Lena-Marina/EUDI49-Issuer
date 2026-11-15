package org.eudi.issuer_ips.controller;

import org.eudi.issuer_ips.model.IssuedAuthorizationCode;
import org.eudi.issuer_ips.model.OAuth2ErrorResponse;
import org.eudi.issuer_ips.model.TokenResponse;
import org.eudi.issuer_ips.service.AccessTokenService;
import org.eudi.issuer_ips.service.AuthorizationCodeService;
import org.eudi.issuer_ips.service.Pkce;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Optional;

import static org.eudi.issuer_ips.model.OAuth2ErrorResponse.*;

/**
 * Token Endpoint (OAuth 2.0 Authorization Code with PKCE S256), for VC-K 5.10.1.
 *
 * POST /token, application/x-www-form-urlencoded:
 *   grant_type=authorization_code, code, redirect_uri, client_id, code_verifier,
 *   optionally authorization_details
 *
 * The code is consumed on the first redemption attempt, also if the check fails afterwards.
 * Missing or duplicate parameters are rejected BEFORE the code is redeemed (invalid_request).
 */
@RestController
public class TokenController {

    static final String CREDENTIAL_CONFIGURATION_ID = "urn:eu.europa.ec.eudi:ips:1";

    /** Exactly what VC-K needs to build the credential request (credential_identifier). */
    static final List<TokenResponse.AuthorizationDetail> AUTHORIZATION_DETAILS = List.of(
            new TokenResponse.AuthorizationDetail(
                    "openid_credential",
                    CREDENTIAL_CONFIGURATION_ID,
                    List.of(CREDENTIAL_CONFIGURATION_ID)));

    private static final List<String> REQUIRED = List.of("code", "redirect_uri", "client_id", "code_verifier");

    private final AuthorizationCodeService authorizationCodeService;
    private final AccessTokenService accessTokenService;

    public TokenController(AuthorizationCodeService authorizationCodeService,
                           AccessTokenService accessTokenService) {
        this.authorizationCodeService = authorizationCodeService;
        this.accessTokenService = accessTokenService;
    }

    @PostMapping("/token")
    public ResponseEntity<?> token(@RequestParam MultiValueMap<String, String> form) {

        // --- 1. form parameters ---------------------------------------------
        for (String name : List.of("grant_type", "code", "redirect_uri", "client_id",
                "code_verifier", "authorization_details")) {
            List<String> values = form.get(name);
            if (values != null && values.size() > 1) {
                return error(INVALID_REQUEST, "Parameter " + name + " ist mehrfach vorhanden.");
            }
        }

        String grantType = form.getFirst("grant_type");
        if (isBlank(grantType)) {
            return error(INVALID_REQUEST, "Parameter grant_type fehlt.");
        }
        if (!"authorization_code".equals(grantType)) {
            return error(UNSUPPORTED_GRANT_TYPE, "Nur grant_type=authorization_code wird unterstützt.");
        }
        for (String name : REQUIRED) {
            if (isBlank(form.getFirst(name))) {
                return error(INVALID_REQUEST, "Parameter " + name + " fehlt.");
            }
        }

        // --- 2. redeem code (exactly once, from here on the code is used up) -
        Optional<IssuedAuthorizationCode> redeemed = authorizationCodeService.redeemCode(form.getFirst("code"));
        if (redeemed.isEmpty()) {
            return error(INVALID_GRANT, "Der Code ist unbekannt, bereits verwendet oder abgelaufen.");
        }
        IssuedAuthorizationCode code = redeemed.get();

        // --- 3. bind code to the request --------------------------------------
        if (!code.clientId().equals(form.getFirst("client_id"))) {
            return error(INVALID_GRANT, "client_id passt nicht zum Code.");
        }
        if (!code.redirectUri().equals(form.getFirst("redirect_uri"))) {
            return error(INVALID_GRANT, "redirect_uri passt nicht zum Code.");
        }
        if (!"S256".equals(code.codeChallengeMethod())
                || !Pkce.verifyS256(form.getFirst("code_verifier"), code.codeChallenge())) {
            return error(INVALID_GRANT, "PKCE-Prüfung fehlgeschlagen.");
        }

        // --- 4. access token, bound to the user identifier (not the patient ID)
        String accessToken = accessTokenService.issue(code.userId());
        TokenResponse body = new TokenResponse(
                accessToken, "Bearer", accessTokenService.expiresInSeconds(), AUTHORIZATION_DETAILS);

        return ResponseEntity.ok()
                .headers(noStore())
                .contentType(MediaType.APPLICATION_JSON)
                .body(body);
    }

    // ------------------------------------------------------------------------

    private static ResponseEntity<OAuth2ErrorResponse> error(String error, String description) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .headers(noStore())
                .contentType(MediaType.APPLICATION_JSON)
                .body(new OAuth2ErrorResponse(error, description));
    }

    /** RFC 6749, section 5.1: token responses must not be cached. */
    private static HttpHeaders noStore() {
        HttpHeaders headers = new HttpHeaders();
        headers.setCacheControl("no-store");
        headers.setPragma("no-cache");
        return headers;
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
