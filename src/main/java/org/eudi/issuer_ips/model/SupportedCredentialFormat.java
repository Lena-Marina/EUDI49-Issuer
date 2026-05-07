package org.eudi.issuer_ips.model;

import com.fasterxml.jackson.annotation.JsonProperty;

public class SupportedCredentialFormat {

    public String format;

    //Nicht notwendig für SD-JWT
    @JsonProperty("docType")
    public String docType;

    // relevant für SD-JWT ! //vct steht für "Verifiable Credential Type"
    @JsonProperty("vct")
    public String vct;

    // Getter & Setter
    public String getFormat() {
        return format;
    }

    public void setFormat(String format) {
        this.format = format;
    }

    //nicht notwendig für SD-JWT !
    public String getDocType() {
        return docType;
    }

    public void setDocType(String docType) {
        this.docType = docType;
    }


    public String getVct() {
        return vct;
    }

    public void setVct(String vct) {
        this.vct = vct;
    }
}
