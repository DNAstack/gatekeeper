package com.dnastack.gatekeeper.challenge;

import com.dnastack.gatekeeper.config.GatekeeperConfig;
import com.dnastack.gatekeeper.config.JsonDefinedFactory;
import com.dnastack.gatekeeper.util.WebFluxUtil;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Objects;

@Slf4j
@RequiredArgsConstructor
public class ErrorHtmlAuthorizationFailureHandler implements AuthorizationFailureHandler {
    private final Config config;

    @Override
    public Mono<Void> handleFailure(ServerWebExchange exchange, GatekeeperConfig.AccessControlItem selectedAccessControlItem) {
        log.debug("Sending authorization error page.");
        final HttpHeaders headers = exchange.getResponse().getHeaders();
        headers.setContentType(MediaType.TEXT_HTML);
        return WebFluxUtil.rewriteResponse(exchange.getResponse(), 200, config.getHtml());
    }

    @Data
    public static class Config {
        private String html;
    }

    @Component("error-html-failure-handler")
    public static class Factory extends JsonDefinedFactory<Config, AuthorizationFailureHandler> {

        @Autowired
        public Factory(ObjectMapper objectMapper) {
            super(objectMapper, log);
        }

        @Override
        protected TypeReference<Config> getConfigType() {
            return new TypeReference<>() {};
        }

        @Override
        protected AuthorizationFailureHandler create(Config config) {
            Objects.requireNonNull(config.getHtml(), "Must define 'html' argument for 'error-html-failure-handler'");
            return new ErrorHtmlAuthorizationFailureHandler(config);
        }

    }

}
