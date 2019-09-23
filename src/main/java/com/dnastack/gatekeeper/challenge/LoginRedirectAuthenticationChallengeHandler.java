package com.dnastack.gatekeeper.challenge;

import com.dnastack.gatekeeper.util.WebFluxUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.URI;

import static java.lang.String.format;

@Slf4j
public
class LoginRedirectAuthenticationChallengeHandler implements AuthenticationChallengeHandler {
    @Override
    public Mono<Void> handleBody(ServerWebExchange exchange) {
        final ServerHttpRequest request = exchange.getRequest();
        final String state = request.getPath().value();
        final String uri = authorizeUrl(state);
        return WebFluxUtil.redirect(exchange, 307, URI.create(uri));

    }

    private String authorizeUrl(String state) {
        return format("/api/identity/login?state=%s", state);
    }

    @Override
    public void addHeaders(ServerHttpResponse response) {
    }
}
