package com.dnastack.gatekeeper.authorizer;

import com.dnastack.gatekeeper.token.InboundTokens;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import lombok.Builder;
import lombok.Singular;
import lombok.Value;

import java.util.List;

public interface TokenAuthorizer {

    @Builder
    @Value
    class AuthorizationDecision {
        boolean allowed;
        @Singular
        List<DecisionInfo> decisionInfos;
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
        String headerValue;

        @Override
        public String getHeaderValue() {
            return headerValue;
        }
    }

    @Value
    class ValidatedToken {
        String rawValue;
        Jws<Claims> jws;
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

    /**
     *
     * @param tokens Will only be called when at least one of the access token or identity token are not null.
     */
    AuthorizationDecision handleTokens(InboundTokens tokens) throws JwtException, IllegalArgumentException;
}
