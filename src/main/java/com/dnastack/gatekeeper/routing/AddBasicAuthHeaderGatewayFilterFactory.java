package com.dnastack.gatekeeper.routing;

import lombok.Data;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.stereotype.Component;

import java.util.Base64;

@Component
public class AddBasicAuthHeaderGatewayFilterFactory extends AbstractGatewayFilterFactory<AddBasicAuthHeaderGatewayFilterFactory.Config> {

	public AddBasicAuthHeaderGatewayFilterFactory() {
		super(Config.class);
	}

	@Override
	public GatewayFilter apply(Config config) {
		final String encodedCredentials = Base64.getEncoder()
												.encodeToString((config.getUsername() + ":" + config.getPassword()).getBytes());
		final String basicAuthValue = "Basic " + encodedCredentials;
		return (exchange, chain) -> chain.filter(exchange.mutate()
														 .request(builder -> builder.header("Authorization",
																							basicAuthValue))
														 .build());
    }

    @Data
    public static class Config {
		private String username, password;
	}

}
