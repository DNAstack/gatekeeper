package com.dnastack.gatekeeper.gateway;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.cloud.gateway.filter.factory.PreserveHostHeaderGatewayFilterFactory;
import org.springframework.cloud.gateway.filter.headers.ForwardedHeadersFilter;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import static org.springframework.cloud.gateway.filter.headers.ForwardedHeadersFilter.FORWARDED_HEADER;
import static org.springframework.cloud.gateway.support.GatewayToStringStyler.filterToStringCreator;
import static org.springframework.cloud.gateway.support.ServerWebExchangeUtils.PRESERVE_HOST_HEADER_ATTRIBUTE;

@Component
public class ForwardedHeaderGatewayFilterFactory extends AbstractGatewayFilterFactory {

    @Autowired
    private ForwardedHeadersFilter filter;

    public GatewayFilter apply() {
        return apply(o -> {
        });
    }

    private void updateHeaders(ServerWebExchange exchange, HttpHeaders headers){
        HttpHeaders newHeaders = filter.filter(exchange.getRequest().getHeaders(), exchange);
        headers.put(FORWARDED_HEADER, newHeaders.get(FORWARDED_HEADER));
    }

    public GatewayFilter apply(Object config) {
        return new GatewayFilter() {
            @Override
            public Mono<Void> filter(ServerWebExchange exchange,
                                     GatewayFilterChain chain) {
                return chain.filter(exchange.mutate()
                                            .request(builder -> builder.headers(headers -> updateHeaders(exchange, headers)))
                                            .build());
            }

            @Override
            public String toString() {
                return filterToStringCreator(ForwardedHeaderGatewayFilterFactory.this)
                        .toString();
            }
        };
    }

}
