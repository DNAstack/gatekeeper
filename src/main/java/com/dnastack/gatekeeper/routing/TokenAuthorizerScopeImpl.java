package com.dnastack.gatekeeper.routing;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.*;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.StringUtils;

import javax.servlet.http.HttpServletResponse;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Slf4j
public class TokenAuthorizerScopeImpl implements ITokenAuthorizer {

    private String controlledPrefix;
    private String registeredPrefix;
    private String publicPrefix;
    private List<String> requiredScopeList;
    private ObjectMapper objectMapper;

    TokenAuthorizerScopeImpl(String controlledPrefix, String registeredPrefix, String publicPrefix, List<String> requiredScopeList, ObjectMapper objectMapper) {
        this.controlledPrefix = controlledPrefix;
        this.registeredPrefix = registeredPrefix;
        this.publicPrefix = publicPrefix;
        this.requiredScopeList = requiredScopeList;
        this.objectMapper = objectMapper;
    }

    @Override
    public String authorizeToken(String authToken, JwtParser jwtParser, HttpServletResponse response) throws UnroutableRequestException {
        try {
            Jws<Claims> jws = jwtParser.parseClaimsJws(authToken);
            log.info("Validated signature of inbound token {}", jws);
            final Claims claims = jws.getBody();

            //1. Get the list of scopes from authtoken
            //2. Make sure that it contains all the scopes that are there in REQUIRED_SCOPE env variable

            List<String> authTokenScopes = (List<String>) claims.get("scope");
            List<String> requiredScopes = requiredScopeList;

            Set<String> authTokenScopesSet = new HashSet<String>(authTokenScopes);
            Set<String> requiredScopesSet = new HashSet<String>(requiredScopes);

            if (authTokenScopesSet.containsAll(requiredScopesSet)) {
                return this.controlledPrefix;
            } else {
                return this.registeredPrefix;
            }
        } catch (ExpiredJwtException ex) {
            log.error("Caught expired exception");
            Utils.setAccessDecision(response, "expired-credentials");
            return Utils.publicPrefixOrAuthChallenge(publicPrefix);
        } catch (JwtException ex) {
            throw new UnroutableRequestException(401, "Invalid token: " + ex);
        }
    }
}
