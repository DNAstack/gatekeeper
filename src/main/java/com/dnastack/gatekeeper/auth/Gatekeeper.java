package com.dnastack.gatekeeper.auth;

import com.dnastack.gatekeeper.auth.ITokenAuthorizer.StandardDecisions;
import io.jsonwebtoken.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

import static java.lang.String.format;

@Service
@Slf4j
public class Gatekeeper {

    @Autowired
    private JwtParser jwtParser;

    // Can't default to empty list when we specify value in application.yml
    @Value("${gatekeeper.token.audiences:#{T(java.util.Collections).emptyList()}}")
    private List<String> acceptedAudiences;

    @Autowired
    private ITokenAuthorizer tokenAuthorizer;

    public ITokenAuthorizer.AuthorizationDecision determineAccessGrant(String authToken) {
        if (authToken == null) {
            log.debug("No auth found. Sending auth challenge.");
            return ITokenAuthorizer.AuthorizationDecision.builder()
                                                         .grant(ITokenAuthorizer.AccessGrant.PUBLIC)
                                                         .decisionInfo(StandardDecisions.REQUIRES_CREDENTIALS)
                                                         .build();
        }

        try {
            final Jws<Claims> jws = parseAndValidateJws(authToken);

            return tokenAuthorizer.authorizeToken(jws);
        } catch (ExpiredJwtException ex) {
            log.error("Caught expired exception");
            return ITokenAuthorizer.AuthorizationDecision.builder()
                                                         .grant(ITokenAuthorizer.AccessGrant.PUBLIC)
                                                         .decisionInfo(StandardDecisions.EXPIRED_CREDENTIALS)
                                                         .build();
        } catch (JwtException ex) {
            return ITokenAuthorizer.AuthorizationDecision.builder()
                                                         .grant(ITokenAuthorizer.AccessGrant.PUBLIC)
                                                         .decisionInfo(StandardDecisions.MALFORMED_CREDENTIALS)
                                                         .decisionInfo(new ITokenAuthorizer.CustomDecisionInfo("Invalid token: " + ex))
                                                         .build();
        }
    }

    private Jws<Claims> parseAndValidateJws(String authToken) {
        final Jws<Claims> jws = jwtParser.parseClaimsJws(authToken);
        if (acceptedAudiences.isEmpty()) {
            log.debug("Not validating token audience, because no audiences are configured.");
        } else {
            final String tokenAudience = Optional.of(jws)
                                                 .map(Jws::getBody)
                                                 .map(Claims::getAudience)
                                                 .orElseThrow(() -> new JwtException(
                                                         "No audience specified in token."));
            final Optional<String> validAudience = acceptedAudiences.stream()
                                                                    .filter(tokenAudience::equals)
                                                                    .findAny();
            if (validAudience.isPresent()) {
                log.debug("Token audience successfully validated [{}]", validAudience.get());
            } else {
                throw new JwtException(format("Token audience [%s] is invalid.", tokenAudience));
            }
        }

        log.info("Validated signature of inbound token {}", jws);
        return jws;
    }

}
