package com.dnastack.gatekeeper.config;

import com.dnastack.gatekeeper.token.JwksFirstSigningKeyResolver;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SigningKeyResolver;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

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
        return new JwksFirstSigningKeyResolver(inboundConfiguration.getJwt());
    }

}
