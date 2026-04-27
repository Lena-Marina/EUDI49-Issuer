package org.eudi.issuer_ips.enums;

import java.util.Arrays;

public enum CredentialFormatEnum {
    NONE("none"),
    JWT_VC("jwt_vc_json"),
    DC_SD_JWT("dc+sd-jwt"),
    JWT_VC_JSON_LD("jwt_vc_json-ld"),
    JSON_LD("ldp_vc"),
    MSO_MDOC("mso_mdoc");

    private final String text;

    CredentialFormatEnum(String text) {
        this.text = text;
    }

    public String getText() {
        return text;
    }

    public static CredentialFormatEnum parse(String text) {
        return Arrays.stream(values())
                .filter(e -> e.text.equals(text))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Unknown format: " + text));
    }
}

/*Valera Reference:
* @Serializable(with = CredentialFormatSerializer::class)
enum class CredentialFormatEnum(val text: String) {
    NONE("none"),
    JWT_VC("jwt_vc_json"),
    DC_SD_JWT("dc+sd-jwt"),
    JWT_VC_JSON_LD("jwt_vc_json-ld"),
    JSON_LD("ldp_vc"),
    MSO_MDOC("mso_mdoc");

    companion object {
        fun parse(text: String) = entries.firstOrNull { it.text == text }
    }
}*/