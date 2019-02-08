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
public class TokenAuthorizerImpl implements ITokenAuthorizer {

    public static final TypeReference<List<GatekeeperRequestRouter.Account>> LIST_OF_ACCOUNT_TYPE = new TypeReference<List<GatekeeperRequestRouter.Account>>() {

    };

    public static final String GOOGLE_ISSUER_URL = "https://accounts.google.com";

    private String tokenAuthorizationMethod;
    private String controlledPrefix;
    private String registeredPrefix;
    private String publicPrefix;
    private List<String> requiredScopeList;
    private InboundEmailWhitelistConfiguration emailWhitelist;
    private ObjectMapper objectMapper;

    TokenAuthorizerImpl(String tokenAuthorizationMethod, String controlledPrefix, String registeredPrefix, String publicPrefix, List<String> requiredScopeList, InboundEmailWhitelistConfiguration emailWhitelist, ObjectMapper objectMapper) {
        this.tokenAuthorizationMethod = tokenAuthorizationMethod;
        this.controlledPrefix = controlledPrefix;
        this.registeredPrefix = registeredPrefix;
        this.publicPrefix = publicPrefix;
        this.requiredScopeList = requiredScopeList;
        this.emailWhitelist = emailWhitelist;
        this.objectMapper = objectMapper;
    }

    @Override
    public String authorizeToken(String authToken, JwtParser jwtParser, HttpServletResponse response) throws UnroutableRequestException {

        try {
            Jws<Claims> jws = jwtParser.parseClaimsJws(authToken);
            log.info("Validated signature of inbound token {}", jws);
            final Claims claims = jws.getBody();

            if (this.tokenAuthorizationMethod.equalsIgnoreCase("email")) {
                return authorizeTokenEmail(authToken, claims);
            } else {
                return authorizeTokenScope(authToken, claims);
            }
        } catch (ExpiredJwtException ex) {
            log.error("Caught expired exception");
            setAccessDecision(response, "expired-credentials");
            return publicPrefixOrAuthChallenge();
        } catch (JwtException ex) {
            throw new UnroutableRequestException(401, "Invalid token: " + ex);
        }
    }

    private Stream<String> extractGoogleEmailAddresses(Claims claims) {
        final List<GatekeeperRequestRouter.Account> accounts = objectMapper.convertValue(claims.get("accounts", List.class),
                LIST_OF_ACCOUNT_TYPE);
        return accounts.stream()
                .filter(this::issuedByGoogle)
                .flatMap(this::accountEmail);
    }


    private String authorizeTokenEmail(String authToken, Claims claims) {

        Stream<String> googleEmails = extractGoogleEmailAddresses(claims);
        final boolean hasWhitelistedEmailAddress = googleEmails.anyMatch(this::isWhitelisted);
        if (hasWhitelistedEmailAddress) {
            //TODO: setAccessDecision(response, "access-granted");
            return controlledPrefix;
        } else {
            //TODO: setAccessDecision(response, "insufficient-credentials");
            return registeredPrefix;
        }
    }

    private String authorizeTokenScope(String authToken, Claims claims) {

        //1. Get the list of scopes from authtoken
        //2. Make sure that it contains all the scopes that are there in REQUIRED_SCOPE env variable

        List<String> authTokenScopes = (List<String>) claims.get("scope");
        List<String> requiredScopes = requiredScopeList;

        Set<String> authTokenScopesSet = new HashSet<String>(authTokenScopes);
        Set<String> requiredScopesSet = new HashSet<String>(requiredScopes);

        if (authTokenScopesSet.containsAll(requiredScopesSet)) {
            return this.controlledPrefix;
        } else {
            return this.publicPrefix;
        }
    }

    private boolean isWhitelisted(String email) {
        return emailWhitelist.getEmailWhitelist().contains(email);
    }

    private Stream<String> accountEmail(GatekeeperRequestRouter.Account account) {
        final String email = account.getEmail();
        return (email == null) ? Stream.empty() : Stream.of(email);
    }

    private boolean issuedByGoogle(GatekeeperRequestRouter.Account account) {
        return GOOGLE_ISSUER_URL.equals(account.getIssuer());
    }

    private String publicPrefixOrAuthChallenge() throws UnroutableRequestException {
        if (StringUtils.isEmpty(publicPrefix)) {
            log.debug("Public prefix is empty. Sending 401 auth challenge.");
            throw new UnroutableRequestException(401, "Anonymous requests not accepted.");
        } else {
            return publicPrefix;
        }
    }

    private void setAccessDecision(HttpServletResponse response, String decision) {
        log.info("Access decision made: {}", decision);
        response.setHeader("X-Gatekeeper-Access-Decision", decision);
    }

}
