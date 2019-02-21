package com.dnastack.gatekeeper.routing;

import com.dnastack.gatekeeper.auth.Gatekeeper;
import com.dnastack.gatekeeper.auth.ITokenAuthorizer.AuthorizationDecision;
import com.dnastack.gatekeeper.auth.ITokenAuthorizer.StandardDecisions;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
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
import java.util.Optional;
import java.util.stream.Stream;

import static java.lang.String.format;

@Component
@Slf4j
public class GatekeeperGatewayFilterFactory extends AbstractGatewayFilterFactory<GatekeeperGatewayFilterFactory.Config> {

    @Autowired
    private Gatekeeper gatekeeper;

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
        final AuthenticationChallengeHandler authenticationChallengeHandler = createUnauthenticatedTokenHandler(config);
        return (exchange, chain) -> doFilter(config, authenticationChallengeHandler, exchange, chain);
    }

    private AuthenticationChallengeHandler createUnauthenticatedTokenHandler(Config config) {
        final String authChallengeHandler = config.getAuthChallengeHandler();
        final String handlerNameSuffix = "AuthenticationChallengeHandler";
        final String fallbackHandlerName = NonInteractiveAuthenticationChallengeHandler.class.getSimpleName()
                                                                                             .replace(handlerNameSuffix,
                                                                                                      "");
        final String handlerName = (authChallengeHandler != null ?
                authChallengeHandler :
                fallbackHandlerName) + handlerNameSuffix;

        final AuthenticationChallengeHandler handler;
        // TODO use bean lookup
        if (handlerName.equals(LoginRedirectAuthenticationChallengeHandler.class.getSimpleName())) {
            handler = new LoginRedirectAuthenticationChallengeHandler();
        } else if (handlerName.equals(NonInteractiveAuthenticationChallengeHandler.class.getSimpleName())) {
            handler = new NonInteractiveAuthenticationChallengeHandler();
        } else {
            throw new IllegalArgumentException("Unrecognized AuthenticationChallengeHandler " + handlerName);
        }

        return handler;
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

    private Mono<Void> doFilter(Config config, AuthenticationChallengeHandler authenticationChallengeHandler, ServerWebExchange exchange, GatewayFilterChain chain) {
        final ServerHttpRequest request = exchange.getRequest();
        final ServerHttpResponse response = exchange.getResponse();
        final Optional<String> foundAuthToken;
        try {
            foundAuthToken = extractAuthToken(request);
        } catch (UnroutableRequestException e) {
            return WebFluxUtils.rewriteResponse(response, e.getStatus(), e.getMessage());
        }

        final AuthorizationDecision authorizationDecision = gatekeeper.determineAccessGrant(foundAuthToken.orElse(null));

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
        final String path = normalizePath(pathPrefix) + stripPrefix(stripPrefix, incomingPath);
        final ServerHttpRequest newRequest = request.mutate().path(path).build();

        return chain.filter(exchange.mutate().request(newRequest).build());
    }

    private String stripPrefix(int stripPrefix, String incomingPath) {
        return Arrays.stream(incomingPath.split("/"))
                     .filter(s -> !s.isEmpty())
                     .skip(stripPrefix)
                     .reduce("",
                             (part1, part2) -> part1 + "/" + part2);
    }

    private Mono<Void> noContentForbidden(ServerHttpResponse response, AuthorizationDecision authorizationDecision) {
        log.debug("Prefix is empty. Sending 403 auth challenge.");
        return WebFluxUtils.rewriteResponse(response, 403,
                                            format("%s requests not accepted.",
                                                   authorizationDecision.getGrant().toString()));

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
        private String authChallengeHandler;
    }

}
