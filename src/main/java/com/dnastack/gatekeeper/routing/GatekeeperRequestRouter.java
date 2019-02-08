package com.dnastack.gatekeeper.routing;

import com.dnastack.gatekeeper.auth.InboundEmailWhitelistConfiguration;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.*;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.stream.Stream;

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

    GatekeeperRequestRouter() throws Exception {
        TokenAuthorizerFactory tokenAuthorizerFactory = new TokenAuthorizerFactory();
        this.tokenAuthorizer = tokenAuthorizerFactory.getTokenAuthorizer(tokenAuthorizationMethod, controlledPrefix, registeredPrefix, publicPrefix, requiredScopeList, emailWhitelist, objectMapper);
    }

    @Override
    public URI route(HttpServletRequest request, HttpServletResponse response) throws URISyntaxException, UnroutableRequestException {

        URI incomingUri = URI.create(request.getRequestURI());
        URI targetBaseUri = URI.create(beaconServerUrl);

        String path = incomingUri.getPath();
        if (path.startsWith("/beacon/")) {
            path = path.substring("/beacon".length());
        }
        String pathPrefix = choosePrefixBasedOnAuth(request, response);
        path = pathPrefix + path;

        return new URI(
                targetBaseUri.getScheme(),
                targetBaseUri.getAuthority(),
                targetBaseUri.getPath() + path,
                incomingUri.getQuery(),
                incomingUri.getFragment());
    }

    private String choosePrefixBasedOnAuth(HttpServletRequest request, HttpServletResponse response) throws UnroutableRequestException {
        String authHeader = request.getHeader("authorization");
        if (authHeader == null) {
            log.debug("No auth found. Sending auth challenge.");
            response.setHeader("WWW-Authenticate", "Bearer");
            final String accessDecision = String.format("requires-credentials %s $.accounts[*].email",
                                                        GOOGLE_ISSUER_URL);
            setAccessDecision(response, accessDecision);
            return publicPrefixOrAuthChallenge();
        }

        String[] parts = authHeader.split(" ");
        if (parts.length != 2) {
            throw new UnroutableRequestException(400, "Invalid authorization header");
        }

        String authScheme = parts[0];
        String authToken = parts[1];

        if (!authScheme.equalsIgnoreCase("bearer")) {
            throw new UnroutableRequestException(400, "Unsupported authorization scheme");
        }

        String prefixString = tokenAuthorizer.authorizeToken(authToken, jwtParser, response);
        return prefixString;
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
}
