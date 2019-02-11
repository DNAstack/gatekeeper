package com.dnastack.gatekeeper.routing;

import com.dnastack.gatekeeper.auth.InboundEmailWhitelistConfiguration;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.*;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Optional;

import static java.lang.String.format;

@Component
@Slf4j
public class GatekeeperRequestRouter implements RequestRouter {

    public static final String GOOGLE_ISSUER_URL = "https://accounts.google.com";

    private ITokenAuthorizer tokenAuthorizer;

    @Value("${gatekeeper.beaconServer.url}")
    private String beaconServerUrl;

    @Value("${gatekeeper.beaconServer.public-prefix}")
    private String publicPrefix;

    @Value("${gatekeeper.token.authorization.method}")
    private String tokenAuthorizationMethod;

    // Can't default to empty list when we specify value in application.yml
    @Value("${gatekeeper.token.audiences:#{T(java.util.Collections).emptyList()}}")
    private List<String> acceptedAudiences;

    @Value("${gatekeeper.required.scope}")
    private List<String> requiredScopeList;

    @Value("${gatekeeper.beaconServer.registered-prefix}")
    private String registeredPrefix;

    @Value("${gatekeeper.beaconServer.controlled-prefix}")
    private String controlledPrefix;

    @Autowired
    private InboundEmailWhitelistConfiguration emailWhitelist;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private JwtParser jwtParser;

    @PostConstruct
    public void init() throws Exception {
        TokenAuthorizerFactory tokenAuthorizerFactory = new TokenAuthorizerFactory();
        this.tokenAuthorizer = tokenAuthorizerFactory.getTokenAuthorizer(tokenAuthorizationMethod, controlledPrefix, registeredPrefix, publicPrefix, requiredScopeList, emailWhitelist, objectMapper);
    }

    @Override
    public URI route(HttpServletRequest request, HttpServletResponse response) throws URISyntaxException, UnroutableRequestException {

        URI incomingUri = URI.create(request.getRequestURI());
        URI targetBaseUri = URI.create(beaconServerUrl);

        String path = incomingUri.getPath();
        path = stripFirstPathPart(path);
        String pathPrefix = choosePrefixBasedOnAuth(request, response);
        path = pathPrefix + path;

        return new URI(
                targetBaseUri.getScheme(),
                targetBaseUri.getAuthority(),
                targetBaseUri.getPath() + path,
                incomingUri.getQuery(),
                incomingUri.getFragment());
    }

    private String stripFirstPathPart(String path) {
        final int secondPartStart = path.indexOf('/', 1);
        return path.substring(secondPartStart);
    }

    private String choosePrefixBasedOnAuth(HttpServletRequest request, HttpServletResponse response) throws UnroutableRequestException {
        final Optional<String> foundAuthToken = extractAuthToken(request);

        if (!foundAuthToken.isPresent()) {
            log.debug("No auth found. Sending auth challenge.");
            response.setHeader("WWW-Authenticate", "Bearer");
            final String accessDecision = format("requires-credentials %s $.accounts[*].email",
                                                        GOOGLE_ISSUER_URL);
            setAccessDecision(response, accessDecision);
            return publicPrefixOrAuthChallenge();
        }

        try {
            final Jws<Claims> jws = parseAndValidateJws(foundAuthToken.get());

            return tokenAuthorizer.authorizeToken(jws, response);
        } catch (ExpiredJwtException ex) {
            log.error("Caught expired exception");
            Utils.setAccessDecision(response, "expired-credentials");
            return Utils.publicPrefixOrAuthChallenge(publicPrefix);
        } catch (JwtException ex) {
            throw new UnroutableRequestException(401, "Invalid token: " + ex);
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
                                                 .orElseThrow(() -> new JwtException("No audience specified in token."));
            final Optional<String> validAudience = acceptedAudiences.stream().filter(tokenAudience::equals).findAny();
            if (validAudience.isPresent()) {
                log.debug("Token audience successfully validated [{}]", validAudience.get());
            } else {
                throw new JwtException(format("Token audience [%s] is invalid.", tokenAudience));
            }
        }

        log.info("Validated signature of inbound token {}", jws);
        return jws;
    }

    private Optional<String> extractAuthToken(HttpServletRequest request) throws UnroutableRequestException {
        final String authHeader = request.getHeader("authorization");

        if (authHeader != null) {
            final String[] parts = Optional.of(authHeader)
                                           .map(value -> value.split(" "))
                                           .filter(values -> values.length == 2)
                                           .orElseThrow(() -> new UnroutableRequestException(400,
                                                                                             "Invalid authorization header"));

            final String authScheme = parts[0];
            if (!authScheme.equalsIgnoreCase("bearer")) {
                throw new UnroutableRequestException(400, "Unsupported authorization scheme");
            }

            return Optional.of(parts[1]);
        } else {
            return Optional.ofNullable(request.getParameter("access_token"));
        }
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

    @Data
    static class Account {
        private String accountId, issuer, email;
    }

    void setBeaconServerUrl(String string) {
		beaconServerUrl = string;		
	}

	void setPublicPrefix(String prefix) {
        this.publicPrefix = prefix;
    }

    void setRegisteredPrefix(String prefix) {
        this.registeredPrefix = prefix;
    }

    void setControlledPrefix(String prefix) {
        this.controlledPrefix = prefix;
    }

    public void setTokenAuthorizationMethod(String tokenAuthorizationMethod) {
        this.tokenAuthorizationMethod = tokenAuthorizationMethod;
    }

    public void setRequiredScopeList(List<String> requiredScopeList) {
        this.requiredScopeList = requiredScopeList;
    }

    public void setEmailWhitelist(InboundEmailWhitelistConfiguration emailWhitelist) {
        this.emailWhitelist = emailWhitelist;
    }
}
