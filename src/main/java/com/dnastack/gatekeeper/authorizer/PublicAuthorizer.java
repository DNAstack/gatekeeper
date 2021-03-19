package com.dnastack.gatekeeper.authorizer;

import com.dnastack.gatekeeper.config.JsonDefinedFactory;
import com.dnastack.gatekeeper.token.InboundTokens;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

public class PublicAuthorizer implements TokenAuthorizer {

    @Override
    public AuthorizationDecision handleNoToken() {
        return AuthorizationDecision.builder()
                                    .allowed(true)
                                    .build();
    }

    @Override
    public AuthorizationDecision handleExpiredToken() {
        return handleNoToken();
    }

    @Override
    public AuthorizationDecision handleInvalidToken() {
        return handleNoToken();
    }

    @Override
    public AuthorizationDecision handleTokens(InboundTokens tokens) {
        return handleNoToken();
    }

    @Slf4j
    @Component("public-authorizer")
    public static class PublicAuthorizerFactory extends JsonDefinedFactory<Object, TokenAuthorizer> {

        @Autowired
        public PublicAuthorizerFactory(ObjectMapper objectMapper) {
            super(objectMapper, log);
        }

        @Override
        protected TypeReference<Object> getConfigType() {
            return new TypeReference<>() { };
        }

        @Override
        protected TokenAuthorizer create(Object config) {
            return new PublicAuthorizer();
        }
    }
}
