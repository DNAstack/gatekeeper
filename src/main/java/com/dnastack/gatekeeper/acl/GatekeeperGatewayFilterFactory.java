package com.dnastack.gatekeeper.acl;

import com.dnastack.gatekeeper.authorizer.TokenAuthorizer;
import com.dnastack.gatekeeper.authorizer.TokenAuthorizer.AuthorizationDecision;
import com.dnastack.gatekeeper.authorizer.TokenAuthorizer.StandardDecisions;
import com.dnastack.gatekeeper.challenge.AuthenticationChallengeHandler;
import com.dnastack.gatekeeper.challenge.LoginRedirectAuthenticationChallengeHandler;
import com.dnastack.gatekeeper.challenge.NonInteractiveAuthenticationChallengeHandler;
import com.dnastack.gatekeeper.config.GatekeeperConfig;
import com.dnastack.gatekeeper.config.JwtConfiguration;
import com.dnastack.gatekeeper.token.TokenParser;
import com.dnastack.gatekeeper.token.TokenUtil;
import com.dnastack.gatekeeper.util.WebFluxUtil;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.cloud.gateway.support.ServerWebExchangeUtils;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static java.lang.String.format;

@Component
@Slf4j
public class GatekeeperGatewayFilterFactory extends AbstractGatewayFilterFactory<GatekeeperConfig.Gateway> {

    @Autowired
    private JwtConfiguration.ParserProvider parserProvider;

    // Can't default to empty list when we specify value in application.yml
    @Value("${gatekeeper.token.audiences:#{T(java.util.Collections).emptyList()}}")
    private List<String> acceptedAudiences;

    @Autowired
    private TokenAuthorizer tokenAuthorizer;

    @Autowired
    private TokenParser tokenParser;

    @Autowired
    private UnsafeBodyParser bodyParser;

    public static final Pattern PATH_VARIABLE_PATTERN = Pattern.compile("\\{([a-zA-Z])}");

    public GatekeeperGatewayFilterFactory() {
        super(GatekeeperConfig.Gateway.class);
    }

    private static void setAccessDecisionHints(ServerHttpResponse response, List<TokenAuthorizer.DecisionInfo> decisionInfos) {
        decisionInfos.forEach(decisionInfo -> setAccessDecisionHint(response, decisionInfo.getHeaderValue()));
    }

    private static void setAccessDecisionHint(ServerHttpResponse response, String decision) {
        log.info("Access decision made: {}", decision);
        response.getHeaders().add("X-Gatekeeper-Access-Decision", decision);
    }

    @Override
    public GatewayFilter apply(GatekeeperConfig.Gateway config) {
        if (config.getAcl().isEmpty()) {
            throw new IllegalArgumentException(format("Gateway [%s] must have a non-empty ACL", config.getId()));
        }
        final AuthenticationChallengeHandler authenticationChallengeHandler = createUnauthenticatedTokenHandler(config);
        return (exchange, chain) -> doFilter(config, authenticationChallengeHandler, exchange, chain);
    }

    private AuthenticationChallengeHandler createUnauthenticatedTokenHandler(GatekeeperConfig.Gateway config) {
        final String authChallengeHandler = config.getAuthChallenger();
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

    private Mono<Void> doFilter(GatekeeperConfig.Gateway config,
                                AuthenticationChallengeHandler authenticationChallengeHandler,
                                ServerWebExchange exchange,
                                GatewayFilterChain chain) {
        final ServerHttpRequest request = exchange.getRequest();
        final ServerHttpResponse response = exchange.getResponse();
        final Optional<String> foundAuthToken;
        try {
            foundAuthToken = TokenUtil.extractAuthToken(request);
        } catch (UnroutableRequestException e) {
            return WebFluxUtil.rewriteResponse(response, e.getStatus(), e.getMessage());
        }

        final AuthorizationDecision accessDecision;
        final GatekeeperConfig.AccessControlItem selectedAccessControlItem;
        final List<TokenAuthorizer.DecisionInfo> authHints;
        {
            Map.Entry<GatekeeperConfig.AccessControlItem, AuthorizationDecision> lastSuccessfulAuth = null, firstFailedAuth = null;
            for (GatekeeperConfig.AccessControlItem accessControlItem : config.getAcl()) {
                Gatekeeper gatekeeper = new Gatekeeper(tokenParser, tokenAuthorizer);
                AuthorizationDecision curDecision = gatekeeper.determineAccessGrant(foundAuthToken.orElse(null));
                if (curDecision.isAllowed()) {
                    lastSuccessfulAuth = Map.entry(accessControlItem, curDecision);
                } else {
                    firstFailedAuth = Map.entry(accessControlItem, curDecision);
                    break;
                }
            }
            if (lastSuccessfulAuth == null && firstFailedAuth == null) {
                throw new IllegalStateException(format("Unable to process ACL for gateway [%s]. Check that ACL is defined.", config.getId()));
            } else if (lastSuccessfulAuth != null) {
                accessDecision = lastSuccessfulAuth.getValue();
                authHints = Optional.ofNullable(firstFailedAuth)
                                    .map(Map.Entry::getValue)
                                    .orElse(lastSuccessfulAuth.getValue())
                                    .getDecisionInfos();
                selectedAccessControlItem = lastSuccessfulAuth.getKey();
            } else {
                accessDecision = firstFailedAuth.getValue();
                authHints = firstFailedAuth.getValue().getDecisionInfos();
                selectedAccessControlItem = firstFailedAuth.getKey();
            }
        }

        // Add headers with decision info here before it's forgotten.
        setAccessDecisionHints(response, authHints);

        if (!accessDecision.isAllowed() || isInvalidCredential(authHints)) {
            if (shouldDoAuthenticationChallenge(authHints)) {
                return doFullAuthChallenge(authenticationChallengeHandler, exchange, response);
            } else {
                return noContentForbidden(response, selectedAccessControlItem);
            }
        } else {
            if (shouldDoAuthenticationChallenge(authHints)) {
                authenticationChallengeHandler.addHeaders(response);
            }

            final String outboundPath = computeOutboundPath(config, exchange, selectedAccessControlItem);
            final ServerHttpRequest newRequest = request.mutate().path(outboundPath).build();

            return chain.filter(exchange.mutate().request(newRequest).build());
        }

    }

    /**
     * Converts patterns like /foo/{bar}/{baz} to paths based on bound variables from Spring Cloud Gateway Path Route Predicate Factory.
     */
    private String computeOutboundPath(GatekeeperConfig.Gateway config, ServerWebExchange exchange, GatekeeperConfig.AccessControlItem accessControlItem) {
        final String outboundExpression = Optional.ofNullable(accessControlItem)
                                                  .map(GatekeeperConfig.AccessControlItem::getOutbound)
                                                  .map(GatekeeperConfig.OutboundRequest::getPath)
                                                  .orElseGet(() -> config.getOutbound().getPath());
        final Matcher pathVariableMatcher = PATH_VARIABLE_PATTERN.matcher(outboundExpression);
        final Map<String, String> boundVariables = ServerWebExchangeUtils.getUriTemplateVariables(exchange);
        final StringBuilder sb = new StringBuilder();
        while (pathVariableMatcher.find()) {
            final String variableName = pathVariableMatcher.group(1);
            pathVariableMatcher.appendReplacement(sb, boundVariables.computeIfAbsent(variableName, name -> {
                throw new IllegalArgumentException(format("Missing variable [%s] used in gateway/acl [%s/%s]",
                                                          name,
                                                          config.getId(),
                                                          accessControlItem.getId()));
            }));
        }
        pathVariableMatcher.appendTail(sb);

        return sb.toString();
    }

    private Mono<Void> doFullAuthChallenge(AuthenticationChallengeHandler authenticationChallengeHandler, ServerWebExchange exchange, ServerHttpResponse response) {
        authenticationChallengeHandler.addHeaders(response);
        return authenticationChallengeHandler.handleBody(exchange);
    }

    private boolean isInvalidCredential(List<TokenAuthorizer.DecisionInfo> decisionInfos) {
        return Stream.of(StandardDecisions.EXPIRED_CREDENTIALS,
                         StandardDecisions.MALFORMED_CREDENTIALS)
                     .anyMatch(decisionInfos::contains);
    }

    private boolean shouldDoAuthenticationChallenge(List<TokenAuthorizer.DecisionInfo> decisionInfos) {
        return Stream.of(StandardDecisions.REQUIRES_CREDENTIALS,
                         StandardDecisions.EXPIRED_CREDENTIALS,
                         StandardDecisions.MALFORMED_CREDENTIALS)
                     .anyMatch(decisionInfos::contains);
    }

    private Mono<Void> noContentForbidden(ServerHttpResponse response, GatekeeperConfig.AccessControlItem accessControlItem) {
        log.debug("Prefix is empty. Sending 403 auth challenge.");
        return WebFluxUtil.rewriteResponse(response, 403,
                                           format("%s requests not accepted.",
                                                   accessControlItem.getId()));

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
