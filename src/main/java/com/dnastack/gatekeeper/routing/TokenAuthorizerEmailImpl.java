package com.dnastack.gatekeeper.routing;

import com.dnastack.gatekeeper.auth.InboundEmailWhitelistConfiguration;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import lombok.extern.slf4j.Slf4j;

import javax.servlet.http.HttpServletResponse;
import java.util.List;
import java.util.stream.Stream;

@Slf4j
public class TokenAuthorizerEmailImpl implements ITokenAuthorizer {

    public static final TypeReference<List<GatekeeperRequestRouter.Account>> LIST_OF_ACCOUNT_TYPE = new TypeReference<List<GatekeeperRequestRouter.Account>>() {

    };

    public static final String GOOGLE_ISSUER_URL = "https://accounts.google.com";

    private String controlledPrefix;
    private String registeredPrefix;
    private String publicPrefix;
    private InboundEmailWhitelistConfiguration emailWhitelist;
    private ObjectMapper objectMapper;

    TokenAuthorizerEmailImpl(String controlledPrefix, String registeredPrefix, String publicPrefix, InboundEmailWhitelistConfiguration emailWhitelist, ObjectMapper objectMapper) {
        this.controlledPrefix = controlledPrefix;
        this.registeredPrefix = registeredPrefix;
        this.publicPrefix = publicPrefix;
        this.emailWhitelist = emailWhitelist;
        this.objectMapper = objectMapper;
    }


    @Override
    public String authorizeToken(Jws<Claims> jws, HttpServletResponse response) {
        log.info("Validated signature of inbound token {}", jws);
        final Claims claims = jws.getBody();

        Stream<String> googleEmails = extractGoogleEmailAddresses(claims);
        final boolean hasWhitelistedEmailAddress = googleEmails.anyMatch(this::isWhitelisted);
        if (hasWhitelistedEmailAddress) {
            Utils.setAccessDecision(response, "access-granted");
            return controlledPrefix;
        } else {
            Utils.setAccessDecision(response, "insufficient-credentials");
            return registeredPrefix;
        }
    }

    private boolean isWhitelisted(String email) {
        return emailWhitelist.getEmailWhitelist().contains(email);
    }

    private Stream<String> accountEmail(GatekeeperRequestRouter.Account account) {
        final String email = account.getEmail();
        return (email == null) ? Stream.empty() : Stream.of(email);
    }

    private boolean issuedByGoogle(GatekeeperRequestRouter.Account account) {
        return GOOGLE_ISSUER_URL.equals(account.getIssuer());
    }

    private Stream<String> extractGoogleEmailAddresses(Claims claims) {
        final List<GatekeeperRequestRouter.Account> accounts = objectMapper.convertValue(claims.get("accounts", List.class),
                LIST_OF_ACCOUNT_TYPE);
        return accounts.stream()
                .filter(this::issuedByGoogle)
                .flatMap(this::accountEmail);
    }
}
