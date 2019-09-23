package com.dnastack.gatekeeper.config;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

@Data
@ConfigurationProperties("gatekeeper")
public class GatekeeperConfig {
    private List<Gateway> gateways;

    @Data
    public static class Gateway {
        private String id;
        private InboundPredicate inbound;
        private OutboundRequest outbound;
        private List<AccessControlItem> acl;
        @JsonProperty("auth-challenge")
        private String authChallenge;
    }

    @Data
    public static class InboundPredicate {
        private String path;
    }

    @Data
    @Builder(toBuilder = true)
    @RequiredArgsConstructor
    @AllArgsConstructor
    public static class OutboundRequest {
        @JsonProperty("base-url")
        private String baseUrl;
        private String path;
        private OutboundAuthentication authentication;
    }

    @Data
    public static class AccessControlItem {
        private String id;
        private TokenAuthorizationConfig authorization;
        private OutboundRequest outbound;
    }

    @Data
    public static class OutboundAuthentication {
        /**
         * Currently only basic-auth-client-authenticator is valid.
         */
        private String method;
        /**
         * Currently only basic auth is supported.
         */
        private UsernamePasswordArgs args;
    }

    @Data
    public static class UsernamePasswordArgs {
        private String username;
        private String password;
    }
}
