package com.dnastack.gatekeeper.acl;

import com.dnastack.gatekeeper.authorizer.TokenAuthorizer;
import com.dnastack.gatekeeper.authorizer.TokenAuthorizer.AuthorizationDecision;
import com.dnastack.gatekeeper.authorizer.TokenAuthorizer.StandardDecisions;
import com.dnastack.gatekeeper.challenge.AuthenticationChallengeHandler;
import com.dnastack.gatekeeper.challenge.LoginRedirectAuthenticationChallengeHandler;
import com.dnastack.gatekeeper.challenge.NonInteractiveAuthenticationChallengeHandler;
import com.dnastack.gatekeeper.config.GatekeeperConfig;
import com.dnastack.gatekeeper.config.JsonDefinedFactory;
import com.dnastack.gatekeeper.config.TokenAuthorizationConfig;
import com.dnastack.gatekeeper.token.TokenParser;
import com.dnastack.gatekeeper.util.TokenUtil;
import com.dnastack.gatekeeper.util.WebFluxUtil;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.cloud.gateway.support.ServerWebExchangeUtils;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static java.lang.String.format;

@Component
@Slf4j
public class GatekeeperGatewayFilterFactory extends AbstractGatewayFilterFactory<GatekeeperConfig.Gateway> {

    public static final Pattern PATH_VARIABLE_PATTERN = Pattern.compile("\\{([a-zA-Z]*)\\}");

    @Autowired
    private TokenParser tokenParser;

    @Autowired
    private BeanFactory beanFactory;

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

        final Map<String, TokenAuthorizer> authorizersByAclItemId =
                config.getAcl()
                      .stream()
                      .map(accessControlItem -> Map.entry(accessControlItem.getId(), createTokenAuthorizer(accessControlItem.getAuthorization())))
                      .collect(Collectors.toConcurrentMap(Map.Entry::getKey, Map.Entry::getValue));
        final AuthenticationChallengeHandler authenticationChallengeHandler = createUnauthenticatedTokenHandler(config);
        return (exchange, chain) -> doFilter(config, authorizersByAclItemId, authenticationChallengeHandler, exchange, chain);
    }

    private TokenAuthorizer createTokenAuthorizer(TokenAuthorizationConfig config) {
        final JsonDefinedFactory<?, TokenAuthorizer> factory = JsonDefinedFactory.lookupFactory(beanFactory, config.getMethod());
        return factory.create(config.getArgs());
    }

    private AuthenticationChallengeHandler createUnauthenticatedTokenHandler(GatekeeperConfig.Gateway config) {
        final String authChallengeHandler = config.getAuthChallenge();
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
                                Map<String, TokenAuthorizer> authorizersByAclItemId, AuthenticationChallengeHandler authenticationChallengeHandler,
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
                final TokenAuthorizer tokenAuthorizer = authorizersByAclItemId.get(accessControlItem.getId());
                if (tokenAuthorizer == null) {
                    throw new IllegalStateException(format("Unitialized authorizer for gateway/accessItem [%s/%s]",
                                                           config.getId(),
                                                           accessControlItem.getId()));
                }
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
            log.debug("Not responding with content for values [allowed={}], [authHints={}]", accessDecision.isAllowed(), authHints);
            if (shouldDoAuthenticationChallenge(authHints)) {
                return doFullAuthChallenge(authenticationChallengeHandler, exchange, response);
            } else {
                return noContentForbidden(response, selectedAccessControlItem);
            }
        } else {
            if (shouldDoAuthenticationChallenge(authHints)) {
                authenticationChallengeHandler.addHeaders(response);
            }

            final String outboundPath = computeOutboundPath(config, selectedAccessControlItem, ServerWebExchangeUtils.getUriTemplateVariables(exchange));
            final ServerHttpRequest newRequest = request.mutate().path(outboundPath).build();

            return chain.filter(exchange.mutate().request(newRequest).build());
        }

    }

    /**
     * Converts patterns like /foo/{bar}/{baz} to paths based on bound variables from Spring Cloud Gateway Path Route Predicate Factory.
     */
    static String computeOutboundPath(GatekeeperConfig.Gateway config, GatekeeperConfig.AccessControlItem accessControlItem, Map<String, String> boundVariables) {
        final String outboundExpression = Optional.of(accessControlItem)
                                                  .map(GatekeeperConfig.AccessControlItem::getOutbound)
                                                  .map(GatekeeperConfig.OutboundRequestConfig::getPath)
                                                  .orElseThrow(() -> new IllegalArgumentException(format("gateway/acl item [%s/%s] is missing outbound path",
                                                                                                         config.getId(),
                                                                                                         accessControlItem.getId())));
        final Matcher pathVariableMatcher = PATH_VARIABLE_PATTERN.matcher(outboundExpression);
        final StringBuilder sb = new StringBuilder();
        while (pathVariableMatcher.find()) {
            final String variableName = pathVariableMatcher.group(1);
            final String variableValue = boundVariables.get(variableName);
            if (variableValue == null) {
                throw new IllegalArgumentException(format("Missing variable [%s] used in gateway/acl [%s/%s]",
                                                          variableName,
                                                          config.getId(),
                                                          accessControlItem.getId()));
            }

            pathVariableMatcher.appendReplacement(sb, variableValue);
        }
        pathVariableMatcher.appendTail(sb);

        if (sb.length() < 1 || sb.charAt(0) != '/') {
            sb.insert(0, '/');
        }

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

    @Data
    public static class Config {
        private int stripPrefix = 1;
        private String publicPrefix;
        private String registeredPrefix;
        private String controlledPrefix;
        private String authChallengeHandler;
    }

}
