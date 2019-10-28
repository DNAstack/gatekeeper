package com.dnastack.gatekeeper.authorizer;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import lombok.Builder;
import lombok.Singular;
import lombok.Value;

import java.util.List;

public interface TokenAuthorizer {

    @Builder
    @Value
    class AuthorizationDecision {
        private boolean allowed;
        @Singular
        private List<DecisionInfo> decisionInfos;
    }

    interface DecisionInfo {
        String getHeaderValue();
    }

    enum StandardDecisions implements DecisionInfo {
        EXPIRED_CREDENTIALS("expired-credentials"),
        MALFORMED_CREDENTIALS("malformed-credentials"),
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

    default AuthorizationDecision handleNoToken() {
        return AuthorizationDecision.builder()
                                    .allowed(false)
                                    .decisionInfo(StandardDecisions.REQUIRES_CREDENTIALS)
                                    .build();
    }

    default AuthorizationDecision handleExpiredToken() {
        return AuthorizationDecision.builder()
                                    .allowed(false)
                                    .decisionInfo(StandardDecisions.EXPIRED_CREDENTIALS)
                                    .build();
    }

    default AuthorizationDecision handleInvalidToken() {
        return AuthorizationDecision.builder()
                                    .allowed(false)
                                    .decisionInfo(StandardDecisions.MALFORMED_CREDENTIALS)
                                    .build();
    }

    AuthorizationDecision handleValidToken(Jws<Claims> jws);
}
