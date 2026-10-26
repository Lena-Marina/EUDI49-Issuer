package org.eudi.issuer_ips.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.Map;

/**
 * configuration with the prefix "issuer" from application.properties.
 *
 * walletClient   : allowed client_id and redirect_uri of the Wallet
 * mockUsers      : username -> (password, user ID)
 * patientMapping : user ID -> Patient ID
 */
@ConfigurationProperties(prefix = "issuer")
public record IssuerProperties(
        WalletClient walletClient,
        Map<String, MockUser> mockUsers,
        Map<String, String> patientMapping
) {

    public IssuerProperties {
        if (walletClient == null
                || isBlank(walletClient.clientId())
                || isBlank(walletClient.redirectUri())) {
            throw new IllegalStateException(
                    "issuer.wallet-client.client-id und issuer.wallet-client.redirect-uri müssen gesetzt sein");
        }
        mockUsers = mockUsers == null ? Map.of() : Map.copyOf(mockUsers);
        patientMapping = patientMapping == null ? Map.of() : Map.copyOf(patientMapping);
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    public record WalletClient(String clientId, String redirectUri) {
    }

    public record MockUser(String password, String userId) {
    }
}