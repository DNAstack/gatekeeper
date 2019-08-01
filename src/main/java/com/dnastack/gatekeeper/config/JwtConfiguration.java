package com.dnastack.gatekeeper.config;

import com.dnastack.gatekeeper.auth.ITokenAuthorizer;
import com.dnastack.gatekeeper.auth.TokenAuthorizerEmailImpl;
import com.dnastack.gatekeeper.auth.TokenAuthorizerScopeImpl;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.security.PublicKey;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

import static java.lang.String.format;

@Configuration
public class JwtConfiguration {

    /**
     * A function mapping issuers to JwtParsers configured to validate signatures from that issuer.
     */
    @FunctionalInterface
    public interface ParserProvider extends Function<String, Optional<JwtParser>> {
        /**
         * @param issuer An issuer url. Never null.
         * @return A JwtParser configured for the given issuer.
         */
        @Override
        Optional<JwtParser> apply(String issuer);
    }

    @Autowired
    private InboundConfiguration inboundConfiguration;

    @Autowired
    private ObjectMapper objectMapper;

    @Bean
    public ParserProvider jwtParser() {
        final Map<String, InboundConfiguration.IssuerConfig> configsByIssuer =
                inboundConfiguration.getJwt()
                                    .stream()
                                    .collect(Collectors.toMap(InboundConfiguration.IssuerConfig::getIssuer,
                                                              Function.identity()));
        return issuer -> Optional.ofNullable(configsByIssuer.get(issuer))
                                 .map(this::createParser);
    }

    private JwtParser createParser(InboundConfiguration.IssuerConfig issuerConfig) {
        if (issuerConfig.getAlgorithm().toLowerCase().startsWith("rs")) {
            final PublicKey publicKey = RsaKeyHelper.parsePublicKey(issuerConfig.getPublicKey());
            return Jwts.parser().setSigningKey(publicKey);
        } else {
            return Jwts.parser().setSigningKey(issuerConfig.getPublicKey());
        }
    }

    @Value("${gatekeeper.token.authorization.method}")
    private String tokenAuthorizationMethod;

    @Value("${gatekeeper.required.scope}")
    private List<String> requiredScopeList;

    @Bean
    public ITokenAuthorizer createTokenAuthorizer() {
        if (tokenAuthorizationMethod.equals("email")) {
            return new TokenAuthorizerEmailImpl(inboundConfiguration.getEmailWhitelist(), objectMapper);
        } else if (tokenAuthorizationMethod.equals("scope")) {
            return new TokenAuthorizerScopeImpl(requiredScopeList);
        } else {
            throw new IllegalArgumentException(format("No suitable token authorizer found for method [%s].",
                                                      tokenAuthorizationMethod));
        }
    }

}
