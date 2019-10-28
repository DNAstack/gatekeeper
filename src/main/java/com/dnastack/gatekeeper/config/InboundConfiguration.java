package com.dnastack.gatekeeper.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;
import java.util.Map;

@Data
@ConfigurationProperties("inbound")
public class InboundConfiguration {
    @Data
    public static class IssuerConfig {
        private String issuer;
        private KeySource keySource;
    }

    @Data
    public static class KeySource {
        private String bean;
        private Map<String, Object> args;
    }

    private List<IssuerConfig> jwt;
}
