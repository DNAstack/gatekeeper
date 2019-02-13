package com.dnastack.gatekeeper.routing;

import com.dnastack.gatekeeper.auth.InboundEmailWhitelistConfiguration;
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

import javax.annotation.PostConstruct;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;

import static java.lang.String.format;

@Component
@Slf4j
public class GatekeeperGatewayFilterFactory extends AbstractGatewayFilterFactory {

    public static final String GOOGLE_ISSUER_URL = "https://accounts.google.com";

    private ITokenAuthorizer tokenAuthorizer;

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
    public GatewayFilter apply(Object config) {
        return this::doFilter;
    }

    private String choosePrefixBasedOnAuth(ServerHttpRequest request, ServerHttpResponse response) throws UnroutableRequestException {
        final Optional<String> foundAuthToken = extractAuthToken(request);

        if (!foundAuthToken.isPresent()) {
            log.debug("No auth found. Sending auth challenge.");
            response.getHeaders().add("WWW-Authenticate", "Bearer");
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

    private String publicPrefixOrAuthChallenge() throws UnroutableRequestException {
        if (StringUtils.isEmpty(publicPrefix)) {
            log.debug("Public prefix is empty. Sending 401 auth challenge.");
            throw new UnroutableRequestException(401, "Anonymous requests not accepted.");
        } else {
            return publicPrefix;
        }
    }

    private void setAccessDecision(ServerHttpResponse response, String decision) {
        log.info("Access decision made: {}", decision);
        response.getHeaders().add("X-Gatekeeper-Access-Decision", decision);
    }

    private Mono<Void> doFilter(ServerWebExchange exchange, GatewayFilterChain chain) {
        final ServerHttpRequest request = exchange.getRequest();
        final ServerHttpResponse response = exchange.getResponse();
        try {
            URI incomingUri = request.getURI();

            final String pathPrefix = choosePrefixBasedOnAuth(request, response);
            final String path = "/" + pathPrefix + incomingUri.getPath();

            final ServerHttpRequest newRequest = request.mutate().path(path).build();

            return chain.filter(exchange.mutate().request(newRequest).build());
        } catch (UnroutableRequestException e) {
            final HttpStatus status = HttpStatus.resolve(e.getStatus());
            final String message = e.getMessage();

            final DataBuffer buffer = response.bufferFactory().wrap(message.getBytes(StandardCharsets.UTF_8));
            response.setStatusCode(status);

            return response.writeWith(Flux.just(buffer));
        }
    }

    @Data
    static class Account {
        private String accountId, issuer, email;
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
