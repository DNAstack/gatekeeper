package com.dnastack.gatekeeper.acl;

import com.dnastack.gatekeeper.authorizer.TokenAuthorizer;
import com.dnastack.gatekeeper.token.InboundTokens;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.util.Optional;
import java.util.UUID;

@Slf4j
@AllArgsConstructor
public class Gatekeeper {

    private TokenAuthorizer tokenAuthorizer;

    public TokenAuthorizer.AuthorizationDecision determineAccessGrant(InboundTokens tokens) {
        final String internalTraceId = UUID.randomUUID().toString();

        if (tokens == null) {
            return tokenAuthorizer.handleNoToken();
        }

        log.debug("R/{}: Access Claims: {}", internalTraceId, extractClaimsOf(tokens.getAccessToken()));
        log.debug("R/{}: ID Claims: {}", internalTraceId, extractClaimsOf(tokens.getIdToken()));

        try {
            log.debug("R/{}: Auth token accepted", internalTraceId);
            return tokenAuthorizer.handleTokens(tokens);
        } catch (ExpiredJwtException ex) {
            log.info("R/{}: Auth token expired: {}", internalTraceId, ex.getMessage());
            return tokenAuthorizer.handleExpiredToken();
        } catch (JwtException | IllegalArgumentException ex) {
            // An IAE exception is thrown when we are using the HS algorithm but the token is signed with RSA
            log.info("R/{}: Auth token rejected: {}", internalTraceId, ex.getMessage());
            return tokenAuthorizer.handleInvalidToken();
        }
    }

    private String extractClaimsOf(String token) {
        return Optional.ofNullable(token).flatMap(t -> Optional.of(t.split("\\.")[0])).orElse(null);
    }

}
