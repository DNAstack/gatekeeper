package com.dnastack.gatekeeper.token;

import brave.Tracing;
import com.dnastack.auth.PermissionChecker;
import com.dnastack.auth.PermissionCheckerFactory;
import com.dnastack.auth.model.IssuerInfo;
import com.dnastack.gatekeeper.config.InboundConfiguration;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.net.URI;
import java.util.Collection;
import java.util.stream.Collectors;

@Configuration
public class PermissionConfig {
    @Bean
    public PermissionChecker permissionChecker(
        InboundConfiguration inboundConfig,
        TokenConfig tokenConfig,
        ConfiguredSigningKeyResolver issuerPubKeyResolver,
        @Value("${gatekeeper.app.url}") String policyEvaluationRequester,
        @Value("${inbound.jwt[0].issuer}") String walletUrl,
        Tracing tracing
    ) {
        final Collection<IssuerInfo> issuerInfos = inboundConfig.getJwt()
            .stream()
            .map(config -> IssuerInfo.IssuerInfoBuilder.builder()
                .issuerUri(config.getIssuer())
                .allowedAudiences(tokenConfig.getAudiences())
                .publicKeyResolver(issuerPubKeyResolver)
                .build())
            .collect(Collectors.toList());
        String policyEvaluationUrl = URI.create(walletUrl).resolve("/policies/evaluations").toString();
        return PermissionCheckerFactory.create(issuerInfos, policyEvaluationRequester, policyEvaluationUrl, tracing);
    }
}
