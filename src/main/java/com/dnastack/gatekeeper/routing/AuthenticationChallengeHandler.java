package com.dnastack.gatekeeper.routing;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategy;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import static java.lang.String.format;

/**
 * Used by the {@link GatekeeperGatewayFilterFactory} for handling unauthenticated responses.
 */
public interface AuthenticationChallengeHandler<C> {
    /**
     * Always called after addHeaders.
     *
     * @param exchange Must not be null.
     * @return A mono for generating the response body for an unauthenticated request.
     */
    Mono<Void> handleBody(ServerWebExchange exchange);

    /**
     * Modify headers on an authenticated response that may still be a 200 with public content.
     *
     * @param response Must not be null.
     */
    void addHeaders(ServerHttpResponse response);

    default void setConfig(C config) {}

    default Class<C> configType() {
        return null;
    }

    default void loadConfig(Object config) {
        final ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.setPropertyNamingStrategy(PropertyNamingStrategy.KEBAB_CASE);
        final Class<C> configType = configType();
        if (configType != null && config != null) {
            final C convertedConfig = objectMapper.convertValue(config, configType);
            if (convertedConfig != null) {
                setConfig(convertedConfig);
            } else {
                throw new IllegalStateException(format("Unable to create config of type [%s] from [%s]",
                                                       configType,
                                                       config));
            }
        }
    }
}
