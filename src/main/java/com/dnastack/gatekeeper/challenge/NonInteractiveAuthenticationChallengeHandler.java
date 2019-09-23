package com.dnastack.gatekeeper.challenge;

import com.dnastack.gatekeeper.util.WebFluxUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Slf4j
public
class NonInteractiveAuthenticationChallengeHandler implements AuthenticationChallengeHandler {
    @Override
    public Mono<Void> handleBody(ServerWebExchange exchange) {
        log.debug("Prefix is empty. Sending 401 auth challenge.");
        return WebFluxUtil.rewriteResponse(exchange.getResponse(), 401, "public requests not accepted.");

    }

    @Override
    public void addHeaders(ServerHttpResponse response) {
        response.getHeaders().add("WWW-Authenticate", "Bearer");
    }
}
