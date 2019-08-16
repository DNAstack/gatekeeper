package com.dnastack.gatekeeper.auth;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.*;
import java.util.stream.Stream;

@Slf4j
public class Ga4ghControlledAccessGrantTokenAuthorizer implements TokenAuthorizer {

    private final GrantConfig grant;
    private final ObjectMapper objectMapper;

    public Ga4ghControlledAccessGrantTokenAuthorizer(GrantConfig grant, ObjectMapper objectMapper) {
        this.grant = grant;
        this.objectMapper = objectMapper;
        Objects.requireNonNull(this.grant, "Must specify ControlledAccessGrant config");
        Objects.requireNonNull(this.grant.getValue(), "Must specify required ControlledAccessGrants value");
        Objects.requireNonNull(this.grant.getSource(), "Must specify required ControlledAccessGrants source");
    }

    @Override
    public AuthorizationDecision authorizeToken(Jws<Claims> jws) {
        log.info("Validated signature of inbound token {}", jws);
        final Claims claims = jws.getBody();

        final Ga4ghControlledAccessGrants controlledAccessGrants = objectMapper.convertValue(claims.get("ga4gh"), Ga4ghControlledAccessGrants.class);
        final Stream<Ga4ghClaim> givenControlledAccessGrants = Optional.ofNullable(controlledAccessGrants)
                                                                       .map(Ga4ghControlledAccessGrants::getControlledAccessGrants)
                                                                       .stream()
                                                                       .flatMap(List::stream)
                                                                       .filter(Objects::nonNull);

        if (givenControlledAccessGrants.anyMatch(this::matches)) {
            return AuthorizationDecision.builder()
                                        .grant(AccessGrant.CONTROLLED)
                                        .decisionInfo(StandardDecisions.ACCESS_GRANTED)
                                        .build();
        } else {
            return AuthorizationDecision.builder()
                                        .grant(AccessGrant.REGISTERED)
                                        .decisionInfo(StandardDecisions.INSUFFICIENT_CREDENTIALS)
                                        .build();
        }
    }

    private boolean matches(Ga4ghClaim givenGrant) {
        final boolean valueMatches = Objects.equals(grant.getValue(), givenGrant.getValue());
        final boolean sourceMatches = Objects.equals(grant.getSource(), givenGrant.getSource());
        // Don't require a by to be configured.
        final boolean byMatches = Optional.ofNullable(grant.getBy())
                                          .map(requiredBy -> Objects.equals(requiredBy, grant.getBy()))
                                          .orElse(true);

        final boolean temporallyValid;
        {
            // TODO check if asserted and expires are required by spec
            // For now we do not require them because the token itself has an iat ane exp
            final Instant now = Instant.now();
            final boolean assertedBeforeNow = Optional.ofNullable(givenGrant.getAsserted())
                                                      .map(asserted -> Instant.ofEpochSecond(asserted).isBefore(now))
                                                      .orElse(true);
            final boolean expiresAfterNow = Optional.ofNullable(givenGrant.getExpires())
                                                    .map(expires -> Instant.ofEpochSecond(expires).isAfter(now))
                                                    .orElse(true);

            temporallyValid = assertedBeforeNow && expiresAfterNow;
        }

        return valueMatches && sourceMatches && byMatches && temporallyValid;
    }

    @Component("ga4gh-controlled-access-grant-authorizer")
    public static class ScopeTokenAuthorizerFactory extends TokenAuthorizerFactory<GrantConfig> {

        @Autowired
        public ScopeTokenAuthorizerFactory(ObjectMapper objectMapper) {
            super(objectMapper);
        }

        @Override
        protected TypeReference<Ga4ghControlledAccessGrantTokenAuthorizer.GrantConfig> getConfigType() {
            return new TypeReference<>() { };
        }

        @Override
        protected TokenAuthorizer create(Ga4ghControlledAccessGrantTokenAuthorizer.GrantConfig grantConfig) {
            return new Ga4ghControlledAccessGrantTokenAuthorizer(grantConfig, objectMapper);
        }

    }

    @Data
    static class Ga4ghControlledAccessGrants {
        @JsonProperty("ControlledAccessGrants")
        private List<Ga4ghClaim> controlledAccessGrants;
    }

    @Data
    static class GrantConfig {
        private String value;
        private String source;
        private String by;
    }
}
