package com.dnastack.gatekeeper.util;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.RedirectToGatewayFilterFactory;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.nio.charset.StandardCharsets;

public class WebFluxUtil {
    public static Mono<Void> rewriteResponse(ServerHttpResponse response, int status, String message) {
        final DataBuffer buffer = response.bufferFactory().wrap(message.getBytes(StandardCharsets.UTF_8));
        response.setStatusCode(HttpStatus.resolve(status));

        return response.writeWith(Flux.just(buffer));
    }

    public static Mono<Void> redirect(ServerWebExchange exchange, int status, URI location) {
        final HttpStatus resolvedStatus = HttpStatus.resolve(status);
        if (resolvedStatus == null || !resolvedStatus.is3xxRedirection()) {
            throw new IllegalArgumentException("Invalid redirect status: " + status);
        }

        final RedirectToGatewayFilterFactory factory = new RedirectToGatewayFilterFactory();
        final GatewayFilter filter = factory.apply(resolvedStatus, location);

        return filter.filter(exchange, e -> Mono.empty());
    }
}
