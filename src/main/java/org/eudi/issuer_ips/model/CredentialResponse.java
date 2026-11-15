package org.eudi.issuer_ips.model;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/**
 * Successful response of POST /credential, exactly as VC-K 5.10.1 expects it
 * (CredentialResponseParameters.extractCredentials):
 *
 *   {"credentials":[{"credential":"<SD-JWT>"}]}
 *
 * Silent traps in VC-K (0 credentials, no error): "credentials" missing,
 * "credential" as object instead of string, Content-Type application/jwt.
 * Deliberately no transaction_id, no notification_id.
 */
public record CredentialResponse(
        @JsonProperty("credentials") List<IssuedCredential> credentials
) {

    public static CredentialResponse single(String credential) {
        return new CredentialResponse(List.of(new IssuedCredential(credential)));
    }

    /**
     * Spring logs response bodies on DEBUG (logging.level.org.springframework.web=DEBUG):
     * the SD-JWT contains health data and must not appear in the log.
     */
    @Override
    public String toString() {
        return "CredentialResponse[credentials=" + (credentials == null ? 0 : credentials.size()) + " x ***]";
    }

    public record IssuedCredential(
            @JsonProperty("credential") String credential
    ) {
        @Override
        public String toString() {
            return "IssuedCredential[credential=***]";
        }
    }
}
