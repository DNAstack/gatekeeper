package com.dnastack.gatekeeper.config;

import com.dnastack.gatekeeper.token.ConfiguredSigningKeyResolver;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SigningKeyResolver;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class JwtConfiguration {

    private final InboundConfiguration inboundConfiguration;
    private final BeanFactory beanFactory;

    @Autowired
    public JwtConfiguration(InboundConfiguration inboundConfiguration, BeanFactory beanFactory) {
        this.inboundConfiguration = inboundConfiguration;
        this.beanFactory = beanFactory;
    }

    @Bean
    public JwtParser jwtParser() {
        return Jwts.parser()
                   .setSigningKeyResolver(resolver());
    }

    private SigningKeyResolver resolver() {
        return new ConfiguredSigningKeyResolver(beanFactory, inboundConfiguration.getJwt());
    }

}
