package com.dnastack.gatekeeper.routing;

import lombok.Data;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.stereotype.Component;

import java.util.Base64;

@Component
public class StripAuthHeaderGatewayFilterFactory extends AbstractGatewayFilterFactory {

	@Override
	public GatewayFilter apply(Object config) {
		return (exchange, chain) -> chain.filter(exchange.mutate()
														 .request(builder -> builder.headers(headers -> headers.remove(
																 "Authorization")))
														 .build());
    }

}
