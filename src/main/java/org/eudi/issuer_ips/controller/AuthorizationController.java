package org.eudi.issuer_ips.controller;

import org.eudi.issuer_ips.config.IssuerProperties;
import org.eudi.issuer_ips.model.PendingAuthorizationRequest;
import org.eudi.issuer_ips.service.AuthenticationProvider;
import org.eudi.issuer_ips.service.AuthorizationCodeService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.HtmlUtils;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

/**
 * Authorization Endpoint (OAuth 2.0 Authorization Code with PKCE) with Mock-Login.
 *
 * GET  /authorize : checks the request from VC-K and shows the login form
 * POST /authorize : verifies username/password and redirects with code and state back to the wallet
 *
 * The controller only knows the AuthenticationProvider interface (swappable).
 */
@RestController
public class AuthorizationController {

    private static final MediaType TEXT_HTML_UTF8 = new MediaType("text", "html", StandardCharsets.UTF_8);

    private static final String MSG_LOGIN_EXPIRED =
            "The login has expired or is invalid. Please restart the issuance in the wallet.";

    private static final String CSS = """
            body { font-family: system-ui, sans-serif; background: #f4f5f7; color: #1d1d1f; margin: 0; }
            main { max-width: 420px; margin: 48px auto; padding: 24px; background: #fff;
                   border-radius: 12px; box-shadow: 0 2px 8px rgba(0,0,0,.08); }
            h1 { font-size: 1.4rem; margin-top: 0; }
            label { display: block; margin-top: 16px; font-weight: 600; }
            input { width: 100%; box-sizing: border-box; padding: 10px; margin-top: 6px;
                    font-size: 1rem; border: 1px solid #c7c9cf; border-radius: 6px; }
            button { margin-top: 24px; width: 100%; padding: 12px; font-size: 1rem;
                     border: 0; border-radius: 6px; background: #1a56db; color: #fff; }
            .error { color: #b42318; background: #fef3f2; padding: 10px; border-radius: 6px; }
            """;

    private final AuthenticationProvider authenticationProvider;
    private final AuthorizationCodeService authorizationCodeService;
    private final IssuerProperties.WalletClient walletClient;

    public AuthorizationController(AuthenticationProvider authenticationProvider,
                                   AuthorizationCodeService authorizationCodeService,
                                   IssuerProperties issuerProperties) {
        this.authenticationProvider = authenticationProvider;
        this.authorizationCodeService = authorizationCodeService;
        this.walletClient = issuerProperties.walletClient();
    }

    /**
     * Parameters of VC-K 5.10.1
     * Unknown Parameter (e.g., prompt=login) are ignored.
     */
    @GetMapping("/authorize")
    public ResponseEntity<String> showLoginForm(
            @RequestParam(name = "response_type", required = false) String responseType,
            @RequestParam(name = "client_id", required = false) String clientId,
            @RequestParam(name = "redirect_uri", required = false) String redirectUri,
            @RequestParam(name = "state", required = false) String state,
            @RequestParam(name = "code_challenge", required = false) String codeChallenge,
            @RequestParam(name = "code_challenge_method", required = false) String codeChallengeMethod,
            @RequestParam(name = "authorization_details", required = false) String authorizationDetails) {

        String error = validateAuthorizationRequest(
                responseType, clientId, redirectUri, codeChallenge, codeChallengeMethod);
        if (error != null) {
            // No Redirect on errors
            return html(HttpStatus.BAD_REQUEST, errorPage(error));
        }

        String requestId = authorizationCodeService.createPendingRequest(
                clientId, redirectUri, state, codeChallenge, codeChallengeMethod, authorizationDetails);
        return html(HttpStatus.OK, loginPage(requestId, null));
    }

    @PostMapping(value = "/authorize", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<String> login(
            @RequestParam(name = "requestId", required = false) String requestId,
            @RequestParam(name = "username", required = false) String username,
            @RequestParam(name = "password", required = false) String password) {

        Optional<PendingAuthorizationRequest> pending = authorizationCodeService.findPendingRequest(requestId);
        if (pending.isEmpty()) {
            return html(HttpStatus.BAD_REQUEST, errorPage(MSG_LOGIN_EXPIRED));
        }

        Optional<String> userId = authenticationProvider.authenticate(username, password);
        if (userId.isEmpty()) {
            // No Code; Formular with the same requestId is shown again
            return html(HttpStatus.UNAUTHORIZED,
                    loginPage(requestId, "Benutzername oder Passwort ist falsch."));
        }

        Optional<String> code = authorizationCodeService.issueCode(requestId, userId.get());
        if (code.isEmpty()) {
            // e.g., simultaneous second login with the same requestId or just expired
            return html(HttpStatus.BAD_REQUEST, errorPage(MSG_LOGIN_EXPIRED));
        }

        PendingAuthorizationRequest request = pending.get();
        String location = buildRedirectLocation(request.redirectUri(), code.get(), request.state());
        return ResponseEntity.status(HttpStatus.FOUND)
                .header(HttpHeaders.LOCATION, location)
                .header(HttpHeaders.CACHE_CONTROL, "no-store")
                .build();
    }

    // ------------------------------------------------------------------------

    /** @return error or null, if the request is valid */
    private String validateAuthorizationRequest(String responseType,
                                                String clientId,
                                                String redirectUri,
                                                String codeChallenge,
                                                String codeChallengeMethod) {
        if (!"code".equals(responseType)) {
            return "Ungültige Anfrage: response_type muss \"code\" sein.";
        }
        if (!walletClient.clientId().equals(clientId)) {
            return "Ungültige Anfrage: unbekannte client_id.";
        }
        if (!walletClient.redirectUri().equals(redirectUri)) {
            return "Ungültige Anfrage: redirect_uri ist nicht erlaubt.";
        }
        if (codeChallenge == null || codeChallenge.isBlank()) {
            return "Ungültige Anfrage: code_challenge fehlt.";
        }
        if (!"S256".equals(codeChallengeMethod)) {
            return "Ungültige Anfrage: code_challenge_method muss \"S256\" sein.";
        }
        return null;
    }

    private static String buildRedirectLocation(String redirectUri, String code, String state) {
        StringBuilder location = new StringBuilder(redirectUri)
                .append(redirectUri.contains("?") ? '&' : '?')
                .append("code=").append(URLEncoder.encode(code, StandardCharsets.UTF_8));
        if (state != null) {
            location.append("&state=").append(URLEncoder.encode(state, StandardCharsets.UTF_8));
        }
        return location.toString();
    }

    private static ResponseEntity<String> html(HttpStatus status, String body) {
        return ResponseEntity.status(status)
                .contentType(TEXT_HTML_UTF8)
                .header(HttpHeaders.CACHE_CONTROL, "no-store")
                .body(body);
    }

    private static String loginPage(String requestId, String errorMessage) {
        String error = errorMessage == null
                ? ""
                : "<p class=\"error\">" + HtmlUtils.htmlEscape(errorMessage) + "</p>\n";
        String form = """
                <form method="post" action="/authorize">
                  <input type="hidden" name="requestId" value="%s">
                  <label for="username">Benutzername</label>
                  <input id="username" name="username" autocomplete="username" required>
                  <label for="password">Passwort</label>
                  <input id="password" name="password" type="password" autocomplete="current-password" required>
                  <button type="submit">Anmelden</button>
                </form>
                """.formatted(HtmlUtils.htmlEscape(requestId));
        return page("Anmeldung beim IPS-Issuer", error + form);
    }

    private static String errorPage(String message) {
        return page("Fehler",
                "<p class=\"error\">" + HtmlUtils.htmlEscape(message) + "</p>\n");
    }

    private static String page(String title, String content) {
        String escapedTitle = HtmlUtils.htmlEscape(title);
        return "<!DOCTYPE html>\n"
                + "<html lang=\"de\">\n"
                + "<head>\n"
                + "<meta charset=\"utf-8\">\n"
                + "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
                + "<title>" + escapedTitle + "</title>\n"
                + "<style>\n" + CSS + "</style>\n"
                + "</head>\n"
                + "<body>\n<main>\n"
                + "<h1>" + escapedTitle + "</h1>\n"
                + content
                + "</main>\n</body>\n</html>\n";
    }
}