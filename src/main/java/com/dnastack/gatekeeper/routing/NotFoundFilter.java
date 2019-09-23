package com.dnastack.gatekeeper.routing;

import lombok.extern.slf4j.Slf4j;
import org.springframework.core.Ordered;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import static org.springframework.http.HttpStatus.NOT_FOUND;

@Slf4j
@Component
public class NotFoundFilter implements WebFilter, Ordered {
    @Override
    public int getOrder() {
        // Run after LoggingWebFilter
        return Ordered.LOWEST_PRECEDENCE;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        return chain.filter(exchange)
                    .onErrorResume(throwable -> {
                                       try {
                                           throw throwable;
                                       } catch (ResponseStatusException rse) {
                                           if (NOT_FOUND.equals(rse.getStatus())) {
                                               log.debug("Converting 404 onError to 404 onNext", rse);
                                               return true;
                                           } else {
                                               return false;
                                           }
                                       } catch (Throwable t) {
                                           return false;
                                       }
                                   },
                                   throwable -> Mono.fromRunnable(() -> exchange.getResponse()
                                                                                .setStatusCode(NOT_FOUND)));
    }
}
