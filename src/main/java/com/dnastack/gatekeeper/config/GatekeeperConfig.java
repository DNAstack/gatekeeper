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
        @JsonProperty("auth-challenger")
        private String authChallenger;
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
        private String url;
        private String path;
        private OutboundAuthorization authorization;
    }

    @Data
    public static class AccessControlItem {
        private String id;
        private TokenAuthorizationConfig authorization;
        private OutboundRequest outbound;
    }

    @Data
    public static class OutboundAuthorization {
        private String username;
        private String password;
    }
}
