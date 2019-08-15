package com.dnastack.gatekeeper.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

@Data
@ConfigurationProperties("inbound")
public class InboundConfiguration {
    @Data
    public static class IssuerConfig {
        private String issuer;
        private String algorithm;
        private String publicKey;
    }

    private List<IssuerConfig> jwt;
}
