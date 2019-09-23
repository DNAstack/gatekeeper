package com.dnastack.gatekeeper.authorizer;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;

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
}
