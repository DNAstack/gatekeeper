package com.dnastack.gatekeeper.auth;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static java.util.stream.Collectors.toList;

@Slf4j
public class ScopeTokenAuthorizer implements TokenAuthorizer {

    private List<String> requiredScopeList;

    public ScopeTokenAuthorizer(List<String> requiredScopeList) {
        this.requiredScopeList = requiredScopeList;
    }

    @Override
    public AuthorizationDecision authorizeToken(Jws<Claims> jws) {
        log.info("Validated signature of inbound token {}", jws);
        final Claims claims = jws.getBody();

        //1. Get the list of scopes from authtoken
        //2. Make sure that it contains all the scopes that are there in REQUIRED_SCOPE env variable

        List<String> authTokenScopes = (List<String>) claims.get("scopes");
        List<String> requiredScopes = requiredScopeList;

        Set<String> authTokenScopesSet = new HashSet<String>(authTokenScopes);
        Set<String> requiredScopesSet = new HashSet<String>(requiredScopes);

        if (authTokenScopesSet.containsAll(requiredScopesSet)) {
            return AuthorizationDecision.builder()
                                        .grant(AccessGrant.CONTROLLED)
                                        .decisionInfo(StandardDecisions.ACCESS_GRANTED)
                                        .build();
        } else {
            return AuthorizationDecision.builder()
                                        .grant(AccessGrant.REGISTERED)
                                        .decisionInfo(StandardDecisions.INSUFFICIENT_CREDENTIALS)
                                        .build();
        }
    }

    @Component("scope-authorizer")
    public static class ScopeTokenAuthorizerFactory extends TokenAuthorizerFactory<ScopeTokenAuthorizerFactory.Config> {

        @Autowired
        public ScopeTokenAuthorizerFactory(ObjectMapper objectMapper) {
            super(objectMapper);
        }

        @Override
        protected TypeReference<Config> getConfigType() {
            return new TypeReference<>() { };
        }

        @Override
        protected TokenAuthorizer create(Config config) {
            return new ScopeTokenAuthorizer(config.scopeList());
        }

        @Data
        public static class Config {
            /*
             A CSV of scopes
             Can't use a list here because depending on how the value is specified, spring config parses it differently
             and Jackson mapping fails.
             */
            private String scopes;

            public List<String> scopeList() {
                return Arrays.stream(scopes.split("\\s*,\\s*")).collect(toList());
            }
        }
    }
}