package com.dnastack.gatekeeper.auth;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import lombok.extern.slf4j.Slf4j;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Slf4j
public class TokenAuthorizerScopeImpl implements ITokenAuthorizer {

    private List<String> requiredScopeList;

    public TokenAuthorizerScopeImpl(List<String> requiredScopeList) {
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
}
