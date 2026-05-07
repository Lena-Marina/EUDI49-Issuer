/*package org.eudi.issuer_ips.model;

public class SupportedCredentialFormat {
    public String format;

    public String getFormat() {
        return format;
    }

    public void setFormat(String format) {
        this.format = format;
    }
}*/
package org.eudi.issuer_ips.model;

import com.fasterxml.jackson.annotation.JsonProperty;

public class SupportedCredentialFormat {

    public String format;

    @JsonProperty("doctype")
    public String docType;

    public String getFormat() { return format; }
    public void setFormat(String format) { this.format = format; }

    public String getDocType() { return docType; }
    public void setDocType(String docType) { this.docType = docType; }
}
