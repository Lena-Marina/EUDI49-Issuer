package org.eudi.issuer_ips;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan
public class IssuerIpsApplication {

    public static void main(String[] args) {
        SpringApplication.run(IssuerIpsApplication.class, args);
    }

}
