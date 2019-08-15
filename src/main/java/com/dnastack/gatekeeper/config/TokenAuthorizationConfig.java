package com.dnastack.gatekeeper.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;
import java.util.Map;

@Data
@ConfigurationProperties("gatekeeper.token.authorization")
public class TokenAuthorizationConfig {
    private String method;
    private Map<String, ?> args;
}
