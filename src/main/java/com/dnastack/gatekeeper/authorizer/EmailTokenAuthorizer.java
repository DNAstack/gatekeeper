package com.dnastack.gatekeeper.authorizer;

import com.dnastack.gatekeeper.config.Account;
import com.dnastack.gatekeeper.config.JsonDefinedFactory;
import com.dnastack.gatekeeper.token.InboundTokens;
import com.dnastack.gatekeeper.token.TokenParser;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

import static java.util.stream.Collectors.toList;

@Slf4j
@RequiredArgsConstructor
public class EmailTokenAuthorizer implements TokenAuthorizer {

    public static final TypeReference<List<Account>> LIST_OF_ACCOUNT_TYPE = new TypeReference<>() {

    };

    public static final String GOOGLE_ISSUER_URL = "https://accounts.google.com";

    private final List<String> emailWhitelist;
    private final ObjectMapper objectMapper;
    private final TokenParser tokenParser;

    @Override
    public AuthorizationDecision handleTokens(InboundTokens tokens) {
        final Claims claims = tokenParser.parseAndValidateJws(tokens.getIdToken()).getBody();

        Stream<String> googleEmails = extractGoogleEmailAddresses(claims);
        final boolean hasWhitelistedEmailAddress = googleEmails.anyMatch(this::isWhitelisted);
        if (hasWhitelistedEmailAddress) {
            return AuthorizationDecision.builder()
                                        .decisionInfo(StandardDecisions.ACCESS_GRANTED)
                                        .build();
        } else {
            return AuthorizationDecision.builder()
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

    @Slf4j
    @Component("email-authorizer")
    public static class EmailTokenAuthorizerFactory extends JsonDefinedFactory<EmailTokenAuthorizerFactory.Config, TokenAuthorizer> {

        private final TokenParser tokenParser;

        @Autowired
        public EmailTokenAuthorizerFactory(ObjectMapper objectMapper, TokenParser tokenParser) {
            super(objectMapper, log);
            this.tokenParser = tokenParser;
        }

        @Override
        protected TypeReference<Config> getConfigType() {
            return new TypeReference<>() { };
        }

        @Override
        protected TokenAuthorizer create(Config config) {
            return new EmailTokenAuthorizer(config.whitelistItems(), objectMapper, tokenParser);
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
