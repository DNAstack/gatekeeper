package com.dnastack.gatekeeper.routing;

import com.dnastack.gatekeeper.auth.InboundEmailWhitelistConfiguration;
import com.dnastack.gatekeeper.routing.ITokenAuthorizer.AccessGrant;
import com.dnastack.gatekeeper.routing.ITokenAuthorizer.AuthorizationDecision;
import com.dnastack.gatekeeper.routing.ITokenAuthorizer.StandardDecisions;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.*;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static java.lang.String.format;

@Component
@Slf4j
public class GatekeeperGatewayFilterFactory extends AbstractGatewayFilterFactory<GatekeeperGatewayFilterFactory.Config> {

    @Value("${gatekeeper.token.authorization.method}")
    private String tokenAuthorizationMethod;

    // Can't default to empty list when we specify value in application.yml
    @Value("${gatekeeper.token.audiences:#{T(java.util.Collections).emptyList()}}")
    private List<String> acceptedAudiences;

    @Value("${gatekeeper.required.scope}")
    private List<String> requiredScopeList;

    @Autowired
    private InboundEmailWhitelistConfiguration emailWhitelist;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private JwtParser jwtParser;

    public GatekeeperGatewayFilterFactory() {
        super(Config.class);
    }

    private static void setAccessDecisionHints(ServerHttpResponse response, AuthorizationDecision authorizationDecision) {
        authorizationDecision.getDecisionInfos()
                             .forEach(decisionInfo -> setAccessDecisionHint(response, decisionInfo.getHeaderValue()));
    }

    private static void setAccessDecisionHint(ServerHttpResponse response, String decision) {
        log.info("Access decision made: {}", decision);
        response.getHeaders().add("X-Gatekeeper-Access-Decision", decision);
    }

    @Override
    public GatewayFilter apply(Config config) {
        final ITokenAuthorizer tokenAuthorizer = createTokenAuthorizer();
        final AuthenticationChallengeHandler authenticationChallengeHandler = createUnauthenticatedTokenHandler(config);
        return (exchange, chain) -> doFilter(config, tokenAuthorizer, authenticationChallengeHandler, exchange, chain);
    }

    private AuthenticationChallengeHandler createUnauthenticatedTokenHandler(Config config) {
        final AuthChallengeHandlerConfig authChallengeHandler = config.getAuthChallengeHandler();
        final String handlerNameSuffix = "AuthenticationChallengeHandler";
        final String fallbackHandlerName = NonInteractiveAuthenticationChallengeHandler.class.getSimpleName()
                                                                                             .replace(handlerNameSuffix,
                                                                                                      "");
        final String handlerName = (authChallengeHandler != null ?
                authChallengeHandler.getName() :
                fallbackHandlerName) + handlerNameSuffix;

        final AuthenticationChallengeHandler<?> handler;
        // TODO use bean lookup
        if (handlerName.equals(LoginRedirectAuthenticationChallengeHandler.class.getSimpleName())) {
            handler = new LoginRedirectAuthenticationChallengeHandler();
        } else if (handlerName.equals(NonInteractiveAuthenticationChallengeHandler.class.getSimpleName())) {
            handler = new NonInteractiveAuthenticationChallengeHandler();
        } else {
            throw new IllegalArgumentException("Unrecognized AuthenticationChallengeHandler " + handlerName);
        }

        final Map<String, Object> args = authChallengeHandler != null ? authChallengeHandler.getArgs() : null;
        handler.loadConfig(args);

        return handler;
    }

    private ITokenAuthorizer createTokenAuthorizer() {
        if (tokenAuthorizationMethod.equals("email")) {
            return new TokenAuthorizerEmailImpl(emailWhitelist, objectMapper);
        } else if (tokenAuthorizationMethod.equals("scope")) {
            return new TokenAuthorizerScopeImpl(requiredScopeList);
        } else {
            throw new IllegalArgumentException(format("No suitable token authorizer found for method [%s].",
                                                      tokenAuthorizationMethod));
        }
    }

    private AuthorizationDecision determineAccessGrant(ITokenAuthorizer tokenAuthorizer, String authToken) {
        if (authToken == null) {
            log.debug("No auth found. Sending auth challenge.");
            return AuthorizationDecision.builder()
                                        .grant(AccessGrant.PUBLIC)
                                        .decisionInfo(StandardDecisions.REQUIRES_CREDENTIALS)
                                        .build();
        }

        try {
            final Jws<Claims> jws = parseAndValidateJws(authToken);

            return tokenAuthorizer.authorizeToken(jws);
        } catch (ExpiredJwtException ex) {
            log.error("Caught expired exception");
            return AuthorizationDecision.builder()
                                        .grant(AccessGrant.PUBLIC)
                                        .decisionInfo(StandardDecisions.EXPIRED_CREDENTIALS)
                                        .build();
        } catch (JwtException ex) {
            return AuthorizationDecision.builder()
                                        .grant(AccessGrant.PUBLIC)
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

    private Optional<String> extractAuthToken(ServerHttpRequest request) throws UnroutableRequestException {
        final String authHeader = request.getHeaders().getFirst("authorization");

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
            return Optional.ofNullable(request.getQueryParams().getFirst("access_token"));
        }
    }

    private Mono<Void> doFilter(Config config, ITokenAuthorizer tokenAuthorizer, AuthenticationChallengeHandler authenticationChallengeHandler, ServerWebExchange exchange, GatewayFilterChain chain) {
        final ServerHttpRequest request = exchange.getRequest();
        final ServerHttpResponse response = exchange.getResponse();
        final Optional<String> foundAuthToken;
        try {
            foundAuthToken = extractAuthToken(request);
        } catch (UnroutableRequestException e) {
            return WebFluxUtils.rewriteResponse(response, e.getStatus(), e.getMessage());
        }

        final AuthorizationDecision authorizationDecision = determineAccessGrant(tokenAuthorizer,
                                                                                 foundAuthToken.orElse(null));

        // Add headers with decision info here before it's forgotten.
        setAccessDecisionHints(response, authorizationDecision);

        final String pathPrefix = authorizationDecision.getGrant().getConfiguredPrefix(config);
        if (StringUtils.isEmpty(pathPrefix)) {
            if (shouldDoAuthenticationChallenge(authorizationDecision)) {
                authenticationChallengeHandler.addHeaders(response);
                return authenticationChallengeHandler.handleBody(exchange);
            } else {
                return noContentForbidden(response, authorizationDecision);
            }
        } else {
            if (shouldDoAuthenticationChallenge(authorizationDecision)) {
                authenticationChallengeHandler.addHeaders(response);
            }
            return supportedAccessLevelResponse(exchange, chain, pathPrefix, config.getStripPrefix());
        }
    }

    private boolean shouldDoAuthenticationChallenge(AuthorizationDecision authorizationDecision) {
        return Stream.of(StandardDecisions.REQUIRES_CREDENTIALS,
                         StandardDecisions.EXPIRED_CREDENTIALS)
                     .anyMatch(decision -> authorizationDecision.getDecisionInfos().contains(decision));
    }

    private Mono<Void> supportedAccessLevelResponse(ServerWebExchange exchange,
                                                    GatewayFilterChain chain,
                                                    String pathPrefix, int stripPrefix) {

        ServerHttpRequest request = exchange.getRequest();
        final String incomingPath = request.getURI().getPath();
        String path = normalizePath(pathPrefix) + stripPrefixKeepingALeadingSlashAtLeast(stripPrefix, incomingPath);
        final ServerHttpRequest newRequest = request.mutate().path(path).build();

        return chain.filter(exchange.mutate().request(newRequest).build());
    }

    /**
     * Helper function to remove the given number of prefixes from the incoming path.
     * Returns at least a single slash if removal of all prefixes evaluates to
     * an empty string.
     *
     * @param n
     * @param incomingPath
     * @return Removes the "n" number of prefixes from the input string and returns at least a single "/"
     */
    private String stripPrefixKeepingALeadingSlashAtLeast(int n, String incomingPath) {
        String result =  Arrays.stream(incomingPath.split("/"))
                     .filter(s -> !s.isEmpty())
                     .skip(n)
                     .reduce("",
                             (part1, part2) -> part1 + "/" + part2);

        if (result.isEmpty()) {
            result = "/";
        }
        return result;
    }

    private Mono<Void> noContentForbidden(ServerHttpResponse response, AuthorizationDecision authorizationDecision) {
        log.debug("Prefix is empty. Sending 403 auth challenge.");
        return WebFluxUtils.rewriteResponse(response, 403,
                                            format("%s requests not accepted.", authorizationDecision.getGrant().toString()));

    }

    /**
     * @param pathPart Part of a path. Must not be null.
     * @return Given part of path normalized to be empty or else have a leading slash and no trailing slash.
     */
    private String normalizePath(String pathPart) {
        return Arrays.stream(pathPart.split("/"))
                     .filter(s -> !s.isEmpty())
                     .reduce("",
                             (part1, part2) -> part1 + "/" + part2);
    }

    @Data
    public static class Config {
        private int stripPrefix = 1;
        private String publicPrefix;
        private String registeredPrefix;
        private String controlledPrefix;
        private AuthChallengeHandlerConfig authChallengeHandler;
    }

    @Data
    public static class AuthChallengeHandlerConfig {
        private String name;
        private Map<String, Object> args;
    }

    @Data
    static class Account {
        private String accountId, issuer, email;
    }

}
