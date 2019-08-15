package com.dnastack.gatekeeper.auth;

import com.dnastack.gatekeeper.config.Account;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

import static java.util.stream.Collectors.toList;

@Slf4j
public class TokenAuthorizerEmailImpl implements ITokenAuthorizer {

    public static final TypeReference<List<Account>> LIST_OF_ACCOUNT_TYPE = new TypeReference<>() {

    };

    public static final String GOOGLE_ISSUER_URL = "https://accounts.google.com";

    private List<String> emailWhitelist;
    private ObjectMapper objectMapper;

    public TokenAuthorizerEmailImpl(List<String> emailWhitelist, ObjectMapper objectMapper) {
        this.emailWhitelist = emailWhitelist;
        this.objectMapper = objectMapper;
    }


    @Override
    public AuthorizationDecision authorizeToken(Jws<Claims> jws) {
        log.info("Validated signature of inbound token {}", jws);
        final Claims claims = jws.getBody();

        Stream<String> googleEmails = extractGoogleEmailAddresses(claims);
        final boolean hasWhitelistedEmailAddress = googleEmails.anyMatch(this::isWhitelisted);
        if (hasWhitelistedEmailAddress) {
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

    private boolean isWhitelisted(String email) {
        return emailWhitelist.contains(email);
    }

    private Stream<String> accountEmail(Account account) {
        final String email = account.getEmail();
        return (email == null) ? Stream.empty() : Stream.of(email);
    }

    private boolean issuedByGoogle(Account account) {
        return GOOGLE_ISSUER_URL.equals(account.getIssuer());
    }

    private Stream<String> extractGoogleEmailAddresses(Claims claims) {
        final List<Account> accounts = objectMapper.convertValue(claims.get("accounts", List.class),
                                                                                                LIST_OF_ACCOUNT_TYPE);
        return accounts.stream()
                .filter(this::issuedByGoogle)
                .flatMap(this::accountEmail);
    }

    @Component("email-authorizer")
    public static class EmailTokenAuthorizerFactory extends TokenAuthorizerFactory<EmailTokenAuthorizerFactory.Config> {

        @Autowired
        public EmailTokenAuthorizerFactory(ObjectMapper objectMapper) {
            super(objectMapper);
        }

        @Override
        protected TypeReference<Config> getConfigType() {
            return new TypeReference<>() { };
        }

        @Override
        protected ITokenAuthorizer create(Config config) {
            return new TokenAuthorizerEmailImpl(config.whitelistItems(), objectMapper);
        }

        @Data
        public static class Config {
            /*
             A CSV of emails
             Can't use a list here because depending on how the value is specified, spring config parses it differently
             and Jackson mapping fails.
             */
            private String whitelist;

            public List<String> whitelistItems() {
                return Arrays.stream(whitelist.split("\\s*,\\s*")).collect(toList());
            }
        }
    }
}
