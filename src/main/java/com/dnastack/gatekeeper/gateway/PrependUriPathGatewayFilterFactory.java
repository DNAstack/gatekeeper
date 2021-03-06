package com.dnastack.gatekeeper.gateway;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.cloud.gateway.filter.factory.PreserveHostHeaderGatewayFilterFactory;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.util.Arrays;
import java.util.List;

@Component
public class PrependUriPathGatewayFilterFactory extends AbstractGatewayFilterFactory<PrependUriPathGatewayFilterFactory.Config> {

	public PrependUriPathGatewayFilterFactory() {
		super(Config.class);
	}

	@Override
	public List<String> shortcutFieldOrder() {
		return Arrays.asList("uri");
	}

	public GatewayFilter apply(String url) {
		return apply(new PrependUriPathGatewayFilterFactory.Config(URI.create(url)));
	}


	@Override
	public GatewayFilter apply(Config config) {
		return (exchange, chain) ->  {
			final ServerHttpRequest request = exchange.getRequest();
			final String path = request.getURI().getRawPath();
			final String newPath = config.getUri().getRawPath() + path;
			ServerHttpRequest newRequest = request.mutate()
												  .path(newPath)
												  .build();

			return chain.filter(exchange.mutate().request(newRequest).build());
		};
	}

	@Data
    @RequiredArgsConstructor
    @AllArgsConstructor
	public static class Config {
		private URI uri;
	}
}
