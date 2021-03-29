package com.dnastack.gatekeeper.authorizer;

import com.dnastack.auth.PermissionChecker;
import com.dnastack.gatekeeper.config.JsonDefinedFactory;
import com.dnastack.gatekeeper.token.InboundTokens;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.parameters.P;
import org.springframework.stereotype.Component;

import java.util.*;

import static java.util.stream.Collectors.toList;

@Slf4j
@RequiredArgsConstructor
public class PolicyTokenAuthorizer implements TokenAuthorizer {

    private final PolicyTokenAuthorizerFactory.Config config;
    private final PermissionChecker permissionChecker;

    @Override
    public AuthorizationDecision handleTokens(InboundTokens tokens) {
        final String requiredResource = config.getResource();
        final Set<String> requiredActions = new HashSet<>(config.actionList());
        final List<String> requiredScopes = config.scopeList();

        try {
            permissionChecker.checkPermissions(tokens.getAccessToken(), requiredScopes, Map.of(requiredResource, requiredActions));
            return AuthorizationDecision.builder()
                .allowed(true)
                .decisionInfo(StandardDecisions.ACCESS_GRANTED)
                .build();
        } catch (Exception exception){
            if (exception instanceof ExpiredJwtException || exception.getCause() instanceof ExpiredJwtException){
                return AuthorizationDecision.builder()
                    .allowed(false)
                    .decisionInfo(StandardDecisions.EXPIRED_CREDENTIALS)
                    .build();
            } else {
                return AuthorizationDecision.builder()
                    .allowed(false)
                    .decisionInfo(StandardDecisions.INSUFFICIENT_CREDENTIALS)
                    .build();
            }
        }
    }

    @Slf4j
    @Component("wallet-policy-authorizer")
    public static class PolicyTokenAuthorizerFactory extends JsonDefinedFactory<PolicyTokenAuthorizerFactory.Config, TokenAuthorizer> {

        private final PermissionChecker permissionChecker;

        @Autowired
        public PolicyTokenAuthorizerFactory(ObjectMapper objectMapper, PermissionChecker permissionChecker) {
            super(objectMapper, log);
            this.permissionChecker = permissionChecker;
        }

        @Override
        protected TypeReference<Config> getConfigType() {
            return new TypeReference<>() { };
        }

        @Override
        protected TokenAuthorizer create(Config config) {
            Objects.requireNonNull(config.getScopes(), "Must defined 'scopes' for wallet-policy-authorizer");
            Objects.requireNonNull(config.getResource(), "Must defined 'resource' for wallet-policy-authorizer");
            Objects.requireNonNull(config.getActions(), "Must defined 'actions' for wallet-policy-authorizer");
            return new PolicyTokenAuthorizer(config, permissionChecker);
        }

        @Data
        public static class Config {
            /*
             A CSV of scopes
             Can't use a list here because depending on how the value is specified, spring config parses it differently
             and Jackson mapping fails.
             */
            private String scopes;
            // A CSV of actions (see above)
            private String actions;

            private String resource;

            public List<String> scopeList() {
                return Arrays.stream(scopes.split("\\s*,\\s*")).collect(toList());
            }

            public List<String> actionList() {
                return Arrays.stream(actions.split("\\s*,\\s*")).collect(toList());
            }
        }
    }
}
