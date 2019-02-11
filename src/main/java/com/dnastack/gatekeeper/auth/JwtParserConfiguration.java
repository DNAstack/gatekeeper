package com.dnastack.gatekeeper.auth;

import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
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
        final PublicKey publicKey = RsaKeyHelper.parsePublicKey(keyConfiguration.getPublicKey());
        return Jwts.parser()
                   .setSigningKey(publicKey);

    }

}
