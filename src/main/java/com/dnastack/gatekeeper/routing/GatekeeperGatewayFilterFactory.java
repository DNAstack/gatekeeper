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

    private static void setAccessDecision(ServerHttpResponse response, AuthorizationDecision authorizationDecision) {
        authorizationDecision.getDecisionInfos()
                             .forEach(decisionInfo -> setAccessDecision(response, decisionInfo.getHeaderValue()));
        if (AccessGrant.PUBLIC.equals(authorizationDecision.getGrant())
                && authorizationDecision.getDecisionInfos()
                                        .contains(
                                                StandardDecisions.REQUIRES_CREDENTIALS)) {
            addAuthenticationChallengeHeaders(response);
        }
    }

    private static void addAuthenticationChallengeHeaders(ServerHttpResponse response) {
        response.getHeaders().add("WWW-Authenticate", "Bearer");
    }

    private static void setAccessDecision(ServerHttpResponse response, String decision) {
        log.info("Access decision made: {}", decision);
        response.getHeaders().add("X-Gatekeeper-Access-Decision", decision);
    }

    @Override
    public GatewayFilter apply(Config config) {
        TokenAuthorizerFactory tokenAuthorizerFactory = new TokenAuthorizerFactory();
        final ITokenAuthorizer tokenAuthorizer = tokenAuthorizerFactory.getTokenAuthorizer(config,
                                                                                           tokenAuthorizationMethod,
                                                                                           requiredScopeList,
                                                                                           emailWhitelist,
                                                                                           objectMapper);
        return (exchange, chain) -> doFilter(config, tokenAuthorizer, exchange, chain);
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

    private Mono<Void> doFilter(Config config, ITokenAuthorizer tokenAuthorizer, ServerWebExchange exchange, GatewayFilterChain chain) {
        final ServerHttpRequest request = exchange.getRequest();
        final ServerHttpResponse response = exchange.getResponse();
        final URI incomingUri = request.getURI();
        final Optional<String> foundAuthToken;
        try {
            foundAuthToken = extractAuthToken(request);
        } catch (UnroutableRequestException e) {
            return rewriteResponse(response, e.getStatus(), e.getMessage());
        }

        final AuthorizationDecision authorizationDecision = determineAccessGrant(tokenAuthorizer,
                                                                                 foundAuthToken.orElse(null));

        // Add headers with decision info here before it's forgotten.
        setAccessDecision(response, authorizationDecision);

        final String pathPrefix = authorizationDecision.getGrant().getConfiguredPrefix(config);
        if (StringUtils.isEmpty(pathPrefix)) {
            log.debug("Prefix is empty. Sending 401 auth challenge.");
            return hardAuthChallenge(response, "Anonymous requests not accepted.");
        } else {
            final String path;
            /*
             * A path prefix of "/" is encoded to mean that the query should go the root of the beacon url.
             * No further prefixes are to be added to beacon url in that case.
             */
            if (StringUtils.isEmpty(pathPrefix)) {
                /* If we're here, it means we're presuming the beacon only accepts controlled access */
                log.debug("Path prefix is empty, not allowing access.");
                return hardAuthChallenge(response, "Unauthorized requests not accepted.");
            } else {
                path = "/" + pathWithNoLeadingOrTrailingSlashes(pathPrefix) + incomingUri.getPath();
            }

            final ServerHttpRequest newRequest = request.mutate().path(path).build();

            return chain.filter(exchange.mutate().request(newRequest).build());
        }
    }

    private String pathWithNoLeadingOrTrailingSlashes(String pathPrefix) {
        return Arrays.stream(pathPrefix.split("/"))
                     .reduce("",
                                                                        (part1, part2) -> part1 + "/" + part2);
    }

    private Mono<Void> hardAuthChallenge(ServerHttpResponse response, String message) {
        return rewriteResponse(response, 401, message);

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
    }

    @Data
    static class Account {
        private String accountId, issuer, email;
    }
}
