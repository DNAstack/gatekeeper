package com.dnastack.gatekeeper.authenticator;

import com.dnastack.gatekeeper.config.JsonDefinedFactory;
import com.dnastack.gatekeeper.gateway.AddBasicAuthHeaderGatewayFilterFactory;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.stereotype.Component;

@Slf4j
@Component("basic-auth-client-authenticator")
public class BasicAuthAuthenicatorFactory extends JsonDefinedFactory<BasicAuthAuthenicatorFactory.Config, GatewayFilter> {

    private final AddBasicAuthHeaderGatewayFilterFactory delegate;

    @Autowired
    public BasicAuthAuthenicatorFactory(ObjectMapper objectMapper, AddBasicAuthHeaderGatewayFilterFactory delegate) {
        super(objectMapper, log);
        this.delegate = delegate;
    }

    @Override
    protected TypeReference<Config> getConfigType() {
        return new TypeReference<>() {};
    }

    @Override
    protected GatewayFilter create(Config config) {
        return delegate.apply(config.getUsername(), config.getPassword());
    }

    @Data
    public static class Config {
        private String username;
        private String password;
    }
}
