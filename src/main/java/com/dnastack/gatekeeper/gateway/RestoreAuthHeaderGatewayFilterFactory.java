package com.dnastack.gatekeeper.gateway;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.stereotype.Component;

import static com.dnastack.gatekeeper.gateway.StripAuthHeaderGatewayFilterFactory.STRIPPED_AUTH_HEADER_KEY;

@Component
public class RestoreAuthHeaderGatewayFilterFactory extends AbstractGatewayFilterFactory {

    @Override
    public GatewayFilter apply(Object config) {
        return (exchange, chain) -> {
            final String authorization = exchange.getAttribute(STRIPPED_AUTH_HEADER_KEY);
            if (authorization != null) {
                return chain.filter(exchange.mutate()
                                            .request(builder -> builder.headers(headers -> headers.add("Authorization", authorization)))
                                            .build());
            } else {
                return chain.filter(exchange);
            }
        };
    }

}
