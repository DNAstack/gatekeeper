package com.dnastack.gatekeeper.config;

import com.dnastack.gatekeeper.challenge.AuthenticationChallengeHandler;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.cloud.gateway.filter.FilterDefinition;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Data
@ConfigurationProperties("gatekeeper")
public class GatekeeperConfig {
    private List<Gateway> gateways;

    @Data
    public static class Gateway {
        private String id;
        private InboundPredicate inbound;
        private BaseOutboundRequestConfig outbound;
        private List<AccessControlItem> acl;
        @JsonProperty("auth-challenge")
        private AuthenticationChallengeHandler.Config authChallenge;
    }

    @Data
    public static class InboundPredicate {
        private String path;
    }

    @Data
    @Builder(toBuilder = true)
    @RequiredArgsConstructor
    @AllArgsConstructor
    public static class BaseOutboundRequestConfig {
        @JsonProperty("base-url")
        private String baseUrl;
        @JsonProperty("authorization-failure")
        private AuthorizationFailureConfig authorizationFailure;
        private OutboundAuthentication authentication;
        @Builder.Default
        private List<FilterDefinition> filters = new ArrayList<>();
    }

    @Data
    @Builder(toBuilder = true)
    @RequiredArgsConstructor
    @AllArgsConstructor
    public static class AuthorizationFailureConfig {
        private String method;
        private Map<String, Object> args;
    }

    @Data
    @Builder(toBuilder = true)
    @RequiredArgsConstructor
    @AllArgsConstructor
    public static class OutboundRequestConfig {
        private String path;
    }

    @Data
    public static class AccessControlItem {
        private String id;
        private TokenAuthorizationConfig authorization;
        private OutboundRequestConfig outbound;
    }

    @Data
    public static class OutboundAuthentication {
        private String method;
        private Map<String, Object> args;
    }
}
