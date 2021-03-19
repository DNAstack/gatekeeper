package com.dnastack.gatekeeper.acl;

import com.dnastack.gatekeeper.authorizer.TokenAuthorizer;
import com.dnastack.gatekeeper.token.InboundTokens;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@AllArgsConstructor
public class Gatekeeper {

    private TokenAuthorizer tokenAuthorizer;

    public TokenAuthorizer.AuthorizationDecision determineAccessGrant(InboundTokens tokens) {
        if (tokens == null) {
            return tokenAuthorizer.handleNoToken();
        }

        try {
            return tokenAuthorizer.handleTokens(tokens);
        } catch (ExpiredJwtException ex) {
            return tokenAuthorizer.handleExpiredToken();
        } catch (JwtException | IllegalArgumentException ex) {
            // An IAE exception is thrown when we are using the HS algorithm but the token is signed with RSA
            log.info("Auth token rejected: {}", ex.getMessage());
            return tokenAuthorizer.handleInvalidToken();
        }
    }

}
