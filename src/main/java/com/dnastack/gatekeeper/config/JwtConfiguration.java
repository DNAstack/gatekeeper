package com.dnastack.gatekeeper.config;

import io.jsonwebtoken.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.security.Key;
import java.security.PublicKey;
import java.util.Objects;

import static java.lang.String.format;

@Configuration
public class JwtConfiguration {

    private InboundConfiguration inboundConfiguration;

    @Autowired
    public JwtConfiguration(InboundConfiguration inboundConfiguration) {
        this.inboundConfiguration = inboundConfiguration;
    }

    @Bean
    public JwtParser jwtParser() {
        return Jwts.parser()
                   .setSigningKeyResolver(resolver());
    }

    private SigningKeyResolver resolver() {
        return new SigningKeyResolverAdapter() {
            @Override
            public Key resolveSigningKey(JwsHeader header, Claims claims) {
                final InboundConfiguration.IssuerConfig issuerConfig = inboundConfiguration.getJwt()
                                                                                           .stream()
                                                                                           .filter(ic -> Objects.equals(ic.getIssuer(), claims.getIssuer()))
                                                                                           .findFirst()
                                                                                           .orElseThrow(() -> new JwtException(format("Unrecognized issuer [%s]", claims.getIssuer())));
                return loadKey(issuerConfig);
            }
        };
    }

    private Key loadKey(InboundConfiguration.IssuerConfig issuerConfig) {
        if (issuerConfig.getAlgorithm().toLowerCase().startsWith("rs")) {
            final PublicKey publicKey = RsaKeyHelper.parsePublicKey(issuerConfig.getPublicKey());
            return publicKey;
        } else {
            throw new IllegalArgumentException(format("Only RS* algorithms supported in gatekeeper: Given algorithm [%s]", issuerConfig.getAlgorithm()));
        }
    }

}
