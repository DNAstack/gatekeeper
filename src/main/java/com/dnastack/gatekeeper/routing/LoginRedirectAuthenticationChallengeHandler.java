package com.dnastack.gatekeeper.routing;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.URI;

import static java.lang.String.format;

@Slf4j
class LoginRedirectAuthenticationChallengeHandler implements AuthenticationChallengeHandler {
    @Override
    public Mono<Void> handleBody(ServerWebExchange exchange) {
        log.debug("Prefix is empty. Sending 401 auth challenge.");
        final ServerHttpRequest request = exchange.getRequest();
        final String state = request.getPath().value();
        final String uri = authorizeUrl(state);
        return WebFluxUtils.redirect(exchange, 307, URI.create(uri));

    }

    private String authorizeUrl(String state) {
        return format("/api/identity/login?state=%s", state);
    }

    @Override
    public void addHeaders(ServerHttpResponse response) {
    }
}
