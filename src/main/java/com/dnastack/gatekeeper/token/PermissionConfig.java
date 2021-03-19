package com.dnastack.gatekeeper.token;

import com.dnastack.auth.PermissionChecker;
import com.dnastack.auth.PermissionCheckerFactory;
import com.dnastack.auth.model.IssuerInfo;
import com.dnastack.gatekeeper.config.InboundConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Collection;
import java.util.stream.Collectors;

@Configuration
public class PermissionConfig {
    @Bean
    public PermissionChecker permissionChecker(InboundConfiguration inboundConfig, TokenConfig tokenConfig, ConfiguredSigningKeyResolver issuerPubKeyResolver) {
        final Collection<IssuerInfo> issuerInfos = inboundConfig.getJwt()
            .stream()
            .map(config -> IssuerInfo.IssuerInfoBuilder.builder()
                .issuerUri(config.getIssuer())
                .allowedAudiences(tokenConfig.getAudiences())
                .publicKeyResolver(issuerPubKeyResolver)
                .build())
            .collect(Collectors.toList());
        return PermissionCheckerFactory.create(issuerInfos);
    }
}
