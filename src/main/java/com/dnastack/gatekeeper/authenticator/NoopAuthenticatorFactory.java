package com.dnastack.gatekeeper.authenticator;

import com.dnastack.gatekeeper.config.JsonDefinedFactory;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.stereotype.Component;

@Slf4j
@Component("noop-client-authenticator")
public class NoopAuthenticatorFactory extends JsonDefinedFactory<Object, GatewayFilter> {
    @Autowired
    protected NoopAuthenticatorFactory(ObjectMapper objectMapper) {
        super(objectMapper, log);
    }

    @Override
    protected TypeReference<Object> getConfigType() {
        return new TypeReference<>() {};
    }

    @Override
    protected GatewayFilter create(Object config) {
        return ((exchange, chain) -> chain.filter(exchange));
    }
}
