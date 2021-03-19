package com.dnastack.gatekeeper.authorizer;

import com.dnastack.gatekeeper.config.JsonDefinedFactory;
import com.dnastack.gatekeeper.token.InboundTokens;
import com.dnastack.gatekeeper.token.TokenParser;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.Optional;

@RequiredArgsConstructor
public class ValidTokenAuthorizer implements TokenAuthorizer {

    private final TokenParser tokenParser;

    @Override
    public AuthorizationDecision handleTokens(InboundTokens tokens) {
        tokenParser.parseAndValidateJws(Optional.ofNullable(tokens.getAccessToken()).orElse(tokens.getIdToken()));

        return AuthorizationDecision.builder()
                                    .allowed(true)
                                    .decisionInfo(StandardDecisions.ACCESS_GRANTED)
                                    .build();
    }

    @Slf4j
    @Component("valid-token-authorizer")
    public static class ValidTokenAuthorizerFactory extends JsonDefinedFactory<Object, TokenAuthorizer> {

        private final TokenParser tokenParser;

        @Autowired
        public ValidTokenAuthorizerFactory(ObjectMapper objectMapper, TokenParser tokenParser) {
            super(objectMapper, log);
            this.tokenParser = tokenParser;
        }

        @Override
        protected TypeReference<Object> getConfigType() {
            return new TypeReference<>() { };
        }

        @Override
        protected TokenAuthorizer create(Object config) {
            return new ValidTokenAuthorizer(tokenParser);
        }
    }
}
