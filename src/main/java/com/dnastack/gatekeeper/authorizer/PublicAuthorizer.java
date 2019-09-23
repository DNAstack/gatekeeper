package com.dnastack.gatekeeper.authorizer;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
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
    public AuthorizationDecision handleValidToken(Jws<Claims> jws) {
        return handleNoToken();
    }

    @Component("public-authorizer")
    public static class PublicAuthorizerFactory extends TokenAuthorizerFactory<Object> {

        @Autowired
        public PublicAuthorizerFactory(ObjectMapper objectMapper) {
            super(objectMapper);
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
