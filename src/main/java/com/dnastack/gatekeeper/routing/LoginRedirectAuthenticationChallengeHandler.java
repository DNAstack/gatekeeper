package com.dnastack.gatekeeper.routing;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.URI;

import static com.dnastack.gatekeeper.header.XForwardUtil.getExternalPath;
import static java.lang.String.format;

@Slf4j
class LoginRedirectAuthenticationChallengeHandler implements AuthenticationChallengeHandler<LoginRedirectAuthenticationChallengeHandler.Config> {
    private Config config;

    @Override
    public Mono<Void> handleBody(ServerWebExchange exchange) {
        log.debug("Prefix is empty. Sending 401 auth challenge.");
        final ServerHttpRequest request = exchange.getRequest();
        final String state = request.getPath().value();
        final String uri = authorizeUrl(redirectUri(exchange), state);
        return WebFluxUtils.redirect(exchange, 307, URI.create(uri));

    }

    private String redirectUri(ServerWebExchange exchange) {
        final ServerHttpRequest request = exchange.getRequest();
        return getExternalPath(request, "/api/identity/token");
    }

    private String authorizeUrl(String redirectUri, String state) {
        return format("%s?response_type=code&client_id=%s&redirect_uri=%s&state=%s",
                      config.getAuthorizeUrl(),
                      config.getClientId(),
                      redirectUri,
                      state);
    }

    @Override
    public void addHeaders(ServerHttpResponse response) {
    }

    @Override
    public Class<Config> configType() {
        return Config.class;
    }

    @Override
    public void setConfig(Config config) {
        this.config = config;
    }

    @Data
    static class Config {
        private String authorizeUrl;
        private String clientId;
    }
}
