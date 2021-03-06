package com.dnastack.gatekeeper.challenge;

import com.dnastack.gatekeeper.acl.GatekeeperGatewayFilterFactory;
import lombok.Data;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Map;

/**
 * Used by the {@link GatekeeperGatewayFilterFactory} for handling unauthenticated responses.
 */
public interface AuthenticationChallengeHandler {
    /**
     * Always called after addHeaders.
     *
     * @param exchange Must not be null.
     * @return A mono for generating the response body for an unauthenticated request.
     */
    Mono<Void> handleBody(ServerWebExchange exchange);

    /**
     * Modify headers on an authenticated response that may still be a 200 with public content.
     *
     * @param response Must not be null.
     */
    void addHeaders(ServerHttpResponse response);

    @Data
    class Config {
        private String handler;
        private Map<String, String> args;
    }
}
