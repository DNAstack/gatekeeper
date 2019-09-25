package com.dnastack.gatekeeper.config;

import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.security.PublicKey;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

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

    private InboundConfiguration inboundConfiguration;

    @Autowired
    public JwtConfiguration(InboundConfiguration inboundConfiguration) {
        this.inboundConfiguration = inboundConfiguration;
    }

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

}
