package com.dnastack.gatekeeper.authenticator;

import com.dnastack.gatekeeper.config.JsonDefinedFactory;
import com.dnastack.gatekeeper.gateway.RestoreAuthHeaderGatewayFilterFactory;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.stereotype.Component;

@Slf4j
@Component("preserve-authorization-client-authenticator")
public class PreserveAuthorizationAuthenticatorFactory extends JsonDefinedFactory<Object, GatewayFilter> {
    private final RestoreAuthHeaderGatewayFilterFactory delegate;

    @Autowired
    protected PreserveAuthorizationAuthenticatorFactory(ObjectMapper objectMapper, RestoreAuthHeaderGatewayFilterFactory delegate) {
        super(objectMapper, log);
        this.delegate = delegate;
    }

    @Override
    protected TypeReference<Object> getConfigType() {
        return new TypeReference<>() {};
    }

    @Override
    protected GatewayFilter create(Object config) {
        return delegate.apply(config);
    }
}
