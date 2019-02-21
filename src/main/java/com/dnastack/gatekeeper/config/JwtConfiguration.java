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

import static java.lang.String.format;

@Configuration
public class JwtConfiguration {

    @Autowired
    private InboundKeyConfiguration keyConfiguration;

    @Autowired
    private ObjectMapper objectMapper;

    @Bean
    public JwtParser jwtParser() {

        if (keyConfiguration.getAlgorithm().toLowerCase().startsWith("rs")) {
            final PublicKey publicKey = RsaKeyHelper.parsePublicKey(keyConfiguration.getPublicKey());
            return Jwts.parser().setSigningKey(publicKey);
        } else {
            return Jwts.parser().setSigningKey(keyConfiguration.getPublicKey());
        }
    }

    @Value("${gatekeeper.token.authorization.method}")
    private String tokenAuthorizationMethod;

    @Value("${gatekeeper.required.scope}")
    private List<String> requiredScopeList;

    @Autowired
    private InboundEmailWhitelistConfiguration emailWhitelist;

    @Bean
    public ITokenAuthorizer createTokenAuthorizer() {
        if (tokenAuthorizationMethod.equals("email")) {
            return new TokenAuthorizerEmailImpl(emailWhitelist, objectMapper);
        } else if (tokenAuthorizationMethod.equals("scope")) {
            return new TokenAuthorizerScopeImpl(requiredScopeList);
        } else {
            throw new IllegalArgumentException(format("No suitable token authorizer found for method [%s].",
                                                      tokenAuthorizationMethod));
        }
    }

}
