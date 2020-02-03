package com.dnastack.gatekeeper.acl;

import com.dnastack.gatekeeper.authorizer.TokenAuthorizer;
import com.dnastack.gatekeeper.authorizer.TokenAuthorizer.StandardDecisions;
import com.dnastack.gatekeeper.config.JwtConfiguration;
import com.dnastack.gatekeeper.token.TokenParser;
import io.jsonwebtoken.*;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

import static java.lang.String.format;

@Slf4j
@AllArgsConstructor
public class Gatekeeper {

    private TokenParser tokenParser;
    private TokenAuthorizer tokenAuthorizer;

    public TokenAuthorizer.AuthorizationDecision determineAccessGrant(String authToken) {
        if (authToken == null) {
            return tokenAuthorizer.handleNoToken();
        }

        try {
            final Jws<Claims> jws = tokenParser.parseAndValidateJws(authToken);

            return tokenAuthorizer.handleValidToken(jws);
        } catch (ExpiredJwtException ex) {
            return tokenAuthorizer.handleExpiredToken();
        } catch (JwtException | IllegalArgumentException ex) {
            // An IAE exception is thrown when we are using the HS algorithm but the token is signed with RSA
            log.info("Auth token rejected: {}", ex.getMessage());
            return tokenAuthorizer.handleInvalidToken();
        }
    }

}
