package com.dnastack.gatekeeper.routing;

import com.dnastack.gatekeeper.auth.InboundEmailWhitelistConfiguration;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.*;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.StringUtils;

import javax.servlet.http.HttpServletResponse;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

@Slf4j
public class TokenAuthorizerScopeImpl implements ITokenAuthorizer {

    public static final String GOOGLE_ISSUER_URL = "https://accounts.google.com";

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
            setAccessDecision(response, "expired-credentials");
            return publicPrefixOrAuthChallenge();
        } catch (JwtException ex) {
            throw new UnroutableRequestException(401, "Invalid token: " + ex);
        }

    }


    private void setAccessDecision(HttpServletResponse response, String decision) {
        log.info("Access decision made: {}", decision);
        response.setHeader("X-Gatekeeper-Access-Decision", decision);
    }

    private String publicPrefixOrAuthChallenge() throws UnroutableRequestException {
        if (StringUtils.isEmpty(publicPrefix)) {
            log.debug("Public prefix is empty. Sending 401 auth challenge.");
            throw new UnroutableRequestException(401, "Anonymous requests not accepted.");
        } else {
            return publicPrefix;
        }
    }

}
