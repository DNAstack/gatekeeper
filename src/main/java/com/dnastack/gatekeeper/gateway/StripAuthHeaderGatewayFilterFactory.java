package com.dnastack.gatekeeper.gateway;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.stereotype.Component;

@Component
public class StripAuthHeaderGatewayFilterFactory extends AbstractGatewayFilterFactory {

	static String STRIPPED_AUTH_HEADER_KEY = "com.dnastack.StripAuthHeader.Header";

	@Override
	public GatewayFilter apply(Object config) {
		return (exchange, chain) -> {
			final String authorization = exchange.getRequest()
												 .getHeaders()
												 .getFirst("Authorization");
			if (authorization != null) {
				exchange.getAttributes().put(STRIPPED_AUTH_HEADER_KEY, authorization);
			}
			return chain.filter(exchange.mutate()
										.request(builder -> builder.headers(headers -> headers.remove(
												"Authorization")))
										.build());
		};
    }

}
