package com.dnastack.gatekeeper.routing;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import lombok.Builder;
import lombok.Singular;
import lombok.Value;

import java.util.List;

public interface ITokenAuthorizer {

    @Builder
    @Value
    class AuthorizationDecision {
        private AccessGrant grant;
        @Singular
        private List<DecisionInfo> decisionInfos;
    }

    enum AccessGrant {
        PUBLIC {
            @Override
            public String getConfiguredPrefix(GatekeeperGatewayFilterFactory.Config config) {
                return config.getPublicPrefix();
            }
        }, REGISTERED {
            @Override
            public String getConfiguredPrefix(GatekeeperGatewayFilterFactory.Config config) {
                return config.getRegisteredPrefix();
            }
        }, CONTROLLED {
            @Override
            public String getConfiguredPrefix(GatekeeperGatewayFilterFactory.Config config) {
                return config.getControlledPrefix();
            }
        };

        public abstract String getConfiguredPrefix(GatekeeperGatewayFilterFactory.Config config);
    }

    interface DecisionInfo {
        String getHeaderValue();
    }

    enum StandardDecisions implements DecisionInfo {
        EXPIRED_CREDENTIALS("expired-credentials"),
        REQUIRES_CREDENTIALS("requires-credentials"),
        INSUFFICIENT_CREDENTIALS("insufficient-credentials"),
        ACCESS_GRANTED("access-granted");

        private final String headerValue;

        StandardDecisions(String headerValue) {
            this.headerValue = headerValue;
        }

        @Override
        public String getHeaderValue() {
            return headerValue;
        }
    }

    @Value
    class CustomDecisionInfo implements DecisionInfo {
        private String headerValue;

        @Override
        public String getHeaderValue() {
            return headerValue;
        }
    }

    AuthorizationDecision authorizeToken(Jws<Claims> jws);

}
