package com.dnastack.gatekeeper.gateway;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.stereotype.Component;

import java.util.Base64;

@Component
public class AddBasicAuthHeaderGatewayFilterFactory extends AbstractGatewayFilterFactory<AddBasicAuthHeaderGatewayFilterFactory.Config> {

	public AddBasicAuthHeaderGatewayFilterFactory() {
		super(Config.class);
	}

	public GatewayFilter apply(String username, String password) {
		return apply(new AddBasicAuthHeaderGatewayFilterFactory.Config(username, password));
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
	@RequiredArgsConstructor
	@AllArgsConstructor
    public static class Config {
		private String username, password;
	}

}
