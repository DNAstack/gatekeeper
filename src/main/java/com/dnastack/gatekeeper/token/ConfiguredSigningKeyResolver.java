package com.dnastack.gatekeeper.token;

import com.dnastack.auth.keyresolver.IssuerPubKeyResolver;
import com.dnastack.auth.model.IssuerKeyIdPair;
import com.dnastack.gatekeeper.config.InboundConfiguration.IssuerConfig;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.SigningKeyResolverAdapter;
import lombok.Value;
import org.springframework.beans.factory.BeanFactory;

import java.security.Key;
import java.util.Collection;
import java.util.concurrent.ConcurrentMap;
import java.util.function.Function;
import java.util.stream.Collectors;

import static com.dnastack.gatekeeper.config.JsonDefinedFactory.createFactoryInstance;
import static java.lang.String.format;

public class ConfiguredSigningKeyResolver extends SigningKeyResolverAdapter implements IssuerPubKeyResolver {

    @Value
    static class RuntimeIssuerInfo {
        IssuerConfig config;
        KeyResolver resolver;
    }

    @FunctionalInterface
    public interface KeyResolver {
        Key resolve(IssuerConfig issuerConfig, String keyId);
    }

    private final ConcurrentMap<String, RuntimeIssuerInfo> infoByIssuer;
    private final BeanFactory beanFactory;

    public ConfiguredSigningKeyResolver(BeanFactory beanFactory, Collection<IssuerConfig> issuerConfigs) {
        this.beanFactory = beanFactory;
        this.infoByIssuer = issuerConfigs.stream()
                                         .map(issuerConfig -> new RuntimeIssuerInfo(issuerConfig,
                                             createFactoryInstance(this.beanFactory, issuerConfig.getBean(), issuerConfig.getArgs())))
                                         .collect(Collectors.toConcurrentMap(info -> info.getConfig().getIssuer(), Function.identity()));
    }

    @Override
    public Key apply(IssuerKeyIdPair issuerKeyIdPair) {
        final String issuer = issuerKeyIdPair.getKey();
        final String keyId = issuerKeyIdPair.getValue();

        final RuntimeIssuerInfo loadedInfo = getRuntimeIssuerInfo(issuer);

        return loadedInfo.getResolver().resolve(loadedInfo.getConfig(), keyId);
    }

    @Override
    public Key resolveSigningKey(JwsHeader header, Claims claims) {
        final RuntimeIssuerInfo loadedInfo = getRuntimeIssuerInfo(claims.getIssuer());

        return loadedInfo.getResolver().resolve(loadedInfo.getConfig(), header.getKeyId());
    }

    private RuntimeIssuerInfo getRuntimeIssuerInfo(String issuer) {
        return infoByIssuer.computeIfAbsent(issuer, iss -> {
            throw new JwtException(format("Unrecognized issuer [%s]", iss));
        });
    }

}
