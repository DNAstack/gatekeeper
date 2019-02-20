package com.dnastack.gatekeeper.routing;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Slf4j
class NonInteractiveAuthenticationChallengeHandler implements AuthenticationChallengeHandler<Object> {
    @Override
    public Mono<Void> handleBody(ServerWebExchange exchange) {
        log.debug("Prefix is empty. Sending 401 auth challenge.");
        return WebFluxUtils.rewriteResponse(exchange.getResponse(), 401, "PUBLIC requests not accepted.");

    }

    @Override
    public void addHeaders(ServerHttpResponse response) {
        response.getHeaders().add("WWW-Authenticate", "Bearer");
    }
}
