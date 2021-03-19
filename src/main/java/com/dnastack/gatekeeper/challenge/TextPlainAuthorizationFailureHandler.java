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
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import static java.lang.String.format;

@Slf4j
@RequiredArgsConstructor
public class TextPlainAuthorizationFailureHandler implements AuthorizationFailureHandler {

    @Override
    public Mono<Void> handleFailure(ServerWebExchange exchange, GatekeeperConfig.AccessControlItem selectedAccessControlItem) {
        log.debug("Prefix is empty. Sending 403 auth challenge.");
        return WebFluxUtil.rewriteResponse(exchange.getResponse(), 403, format("%s requests not accepted.", selectedAccessControlItem.getId()));
    }

    @Data
    public static class Config {}

    @Component("text/plain-failure-handler")
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
            return new TextPlainAuthorizationFailureHandler();
        }

    }

}
