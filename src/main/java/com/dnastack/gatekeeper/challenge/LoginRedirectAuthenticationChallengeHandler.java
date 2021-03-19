package com.dnastack.gatekeeper.challenge;

import com.dnastack.gatekeeper.util.WebFluxUtil;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;

import java.net.URI;

import static java.lang.String.format;

@Slf4j
@RequiredArgsConstructor
public class LoginRedirectAuthenticationChallengeHandler implements AuthenticationChallengeHandler {
    private final Config config;

    @Override
    public Mono<Void> handleBody(ServerWebExchange exchange) {
        final ServerHttpRequest request = exchange.getRequest();
        final String state = request.getPath().value();
        final URI uri = authorizeUrl(state);
        return WebFluxUtil.redirect(exchange, 302, uri);

    }

    private URI authorizeUrl(String state) {
        final UriComponentsBuilder uriBuilder = UriComponentsBuilder.fromPath("/api/identity/login");
        if (config != null) {
            if (config.getScopes() != null) {
                uriBuilder.queryParam("scope", config.getScopes());
            }
            if (config.getResource() != null) {
                uriBuilder.queryParam("resource", config.getResource());
            }
        }
        uriBuilder.queryParam("state", state);

        return uriBuilder.build().toUri();
    }

    @Override
    public void addHeaders(ServerHttpResponse response) {
    }

    @Data
    public static class Config {
        private String scopes;
        private String resource;
    }
}
