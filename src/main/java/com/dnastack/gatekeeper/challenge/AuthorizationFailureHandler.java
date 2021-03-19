package com.dnastack.gatekeeper.challenge;

import com.dnastack.gatekeeper.acl.GatekeeperGatewayFilterFactory;
import com.dnastack.gatekeeper.config.GatekeeperConfig;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Used by the {@link GatekeeperGatewayFilterFactory} for handling unauthorized responses.
 */
public interface AuthorizationFailureHandler {
    /**
     * @param exchange Must not be null.
     * @param selectedAccessControlItem
     * @return A mono for generating the response for an unauthenticated request.
     */
    Mono<Void> handleFailure(ServerWebExchange exchange, GatekeeperConfig.AccessControlItem selectedAccessControlItem);
}
