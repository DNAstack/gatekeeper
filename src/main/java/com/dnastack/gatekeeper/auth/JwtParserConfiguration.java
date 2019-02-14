package com.dnastack.gatekeeper.auth;

import io.jsonwebtoken.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.security.PublicKey;

@Configuration
public class JwtParserConfiguration {

    @Autowired
    private InboundKeyConfiguration keyConfiguration;

    @Bean
    public JwtParser jwtParser() {

        if (keyConfiguration.getAlgorithm().toLowerCase().startsWith("rs")) {
            final PublicKey publicKey = RsaKeyHelper.parsePublicKey(keyConfiguration.getPublicKey());
            return Jwts.parser().setSigningKey(publicKey);
        } else {
            return Jwts.parser().setSigningKey(keyConfiguration.getPublicKey());
        }
    }

}
