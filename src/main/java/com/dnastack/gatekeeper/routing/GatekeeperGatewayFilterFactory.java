package com.dnastack.gatekeeper.routing;

import com.dnastack.gatekeeper.auth.InboundEmailWhitelistConfiguration;
import com.dnastack.gatekeeper.routing.ITokenAuthorizer.AccessGrant;
import com.dnastack.gatekeeper.routing.ITokenAuthorizer.AuthorizationDecision;
import com.dnastack.gatekeeper.routing.ITokenAuthorizer.StandardDecisions;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
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
                             .forEach(decisionInfo -> setAccessDecision(response, decisionInfo.getHeaderValue()));
    }

    private static void setAccessDecision(ServerHttpResponse response, String decision) {
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
        final Boolean redirectToLogin = Optional.ofNullable(config.getRedirectToLogin()).orElse(false);
        if (redirectToLogin) {
            // TODO implement login redirect
//            return new LoginRedirectAuthenticationChallengeHandler(URI.create("http://localhost:8081"));
            return new NonInteractiveAuthenticationChallengeHandler();
        } else {
            return new NonInteractiveAuthenticationChallengeHandler();
        }
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
            return rewriteResponse(response, e.getStatus(), e.getMessage());
        }

        final AuthorizationDecision authorizationDecision = determineAccessGrant(tokenAuthorizer,
                                                                                 foundAuthToken.orElse(null));

        // Add headers with decision info here before it's forgotten.
        setAccessDecisionHints(response, authorizationDecision);

        final String pathPrefix = authorizationDecision.getGrant().getConfiguredPrefix(config);
        if (StringUtils.isEmpty(pathPrefix)) {
            if (shouldDoAuthenticationChallenge(authorizationDecision)) {
                authenticationChallengeHandler.addHeaders(response);
                return authenticationChallengeHandler.handleBody(response);
            } else {
                return noContentForbidden(response, authorizationDecision);
            }
        } else {
            if (shouldDoAuthenticationChallenge(authorizationDecision)) {
                authenticationChallengeHandler.addHeaders(response);
            }
            return supportedAccessLevelResponse(exchange, chain, pathPrefix);
        }
    }

    private boolean shouldDoAuthenticationChallenge(AuthorizationDecision authorizationDecision) {
        return Stream.of(StandardDecisions.REQUIRES_CREDENTIALS,
                         StandardDecisions.EXPIRED_CREDENTIALS)
                     .anyMatch(decision -> authorizationDecision.getDecisionInfos().contains(decision));
    }

    private Mono<Void> supportedAccessLevelResponse(ServerWebExchange exchange,
                                                    GatewayFilterChain chain,
                                                    String pathPrefix) {

        ServerHttpRequest request = exchange.getRequest();
        final String incomingPath = request.getURI().getPath();
        final String path = "/" + pathWithNoLeadingOrTrailingSlashes(pathPrefix) + incomingPath;
        final ServerHttpRequest newRequest = request.mutate().path(path).build();

        return chain.filter(exchange.mutate().request(newRequest).build());
    }

    private Mono<Void> noContentForbidden(ServerHttpResponse response, AuthorizationDecision authorizationDecision) {
        log.debug("Prefix is empty. Sending 403 auth challenge.");
        return rewriteResponse(response, 403,
                               format("%s requests not accepted.", authorizationDecision.getGrant().toString()));

    }

    private String pathWithNoLeadingOrTrailingSlashes(String pathPrefix) {
        return Arrays.stream(pathPrefix.split("/"))
                     .reduce("",
                                                                        (part1, part2) -> part1 + "/" + part2);
    }

    private Mono<Void> rewriteResponse(ServerHttpResponse response, int status, String message) {
        final DataBuffer buffer = response.bufferFactory().wrap(message.getBytes(StandardCharsets.UTF_8));
        response.setStatusCode(HttpStatus.resolve(status));

        return response.writeWith(Flux.just(buffer));
    }

    @Data
    public static class Config {
        private String publicPrefix;
        private String registeredPrefix;
        private String controlledPrefix;
        private Boolean redirectToLogin;
    }

    @Data
    static class Account {
        private String accountId, issuer, email;
    }

    private class NonInteractiveAuthenticationChallengeHandler implements AuthenticationChallengeHandler {
        @Override
        public Mono<Void> handleBody(ServerHttpResponse response) {
            log.debug("Prefix is empty. Sending 401 auth challenge.");
            return rewriteResponse(response, 401, "PUBLIC requests not accepted.");

        }

        @Override
        public void addHeaders(ServerHttpResponse response) {
            response.getHeaders().add("WWW-Authenticate", "Bearer");
        }
    }

    @AllArgsConstructor
    private class LoginRedirectAuthenticationChallengeHandler implements AuthenticationChallengeHandler {
        private URI location;

        @Override
        public Mono<Void> handleBody(ServerHttpResponse response) {
            log.debug("Prefix is empty. Sending 401 auth challenge.");
            return rewriteResponse(response, 307, "");

        }

        @Override
        public void addHeaders(ServerHttpResponse response) {
            response.getHeaders().setLocation(location);
        }
    }
}
