package com.dnastack.gatekeeper.authorizer;

import com.dnastack.gatekeeper.config.JsonDefinedFactory;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

public class ValidTokenAuthorizer implements TokenAuthorizer {

    @Override
    public AuthorizationDecision handleValidToken(Jws<Claims> jws) {
        return AuthorizationDecision.builder()
                                    .allowed(true)
                                    .decisionInfo(StandardDecisions.ACCESS_GRANTED)
                                    .build();
    }

    @Slf4j
    @Component("valid-token-authorizer")
    public static class ValidTokenAuthorizerFactory extends JsonDefinedFactory<Object, TokenAuthorizer> {

        @Autowired
        public ValidTokenAuthorizerFactory(ObjectMapper objectMapper) {
            super(objectMapper, log);
        }

        @Override
        protected TypeReference<Object> getConfigType() {
            return new TypeReference<>() { };
        }

        @Override
        protected TokenAuthorizer create(Object config) {
            return new ValidTokenAuthorizer();
        }
    }
}
