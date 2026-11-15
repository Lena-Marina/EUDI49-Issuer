package org.eudi.issuer_ips.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Clock;

/**
 * One clock for all expiry checks (authorization codes, access tokens).
 * Tests replace it with a controllable clock.
 */
@Configuration
public class ClockConfig {

    @Bean
    public Clock clock() {
        return Clock.systemUTC();
    }
}
