package com.dnastack.gatekeeper.token;

import com.dnastack.gatekeeper.config.InboundConfiguration.IssuerConfig;
import com.dnastack.gatekeeper.config.JsonDefinedFactory;
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

import static com.dnastack.gatekeeper.config.JsonDefinedFactory.lookupFactory;
import static java.lang.String.format;

public class ConfiguredSigningKeyResolver extends SigningKeyResolverAdapter {

    @Value
    static class RuntimeIssuerInfo {
        IssuerConfig config;
        KeyResolver resolver;
    }

    @FunctionalInterface
    public interface KeyResolver {
        Key resolve(IssuerConfig issuerConfig, JwsHeader header);
    }

    private final ConcurrentMap<String, RuntimeIssuerInfo> infoByIssuer;
    private final BeanFactory beanFactory;

    public ConfiguredSigningKeyResolver(BeanFactory beanFactory, Collection<IssuerConfig> issuerConfigs) {
        this.beanFactory = beanFactory;
        this.infoByIssuer = issuerConfigs.stream()
                                         .map(issuerConfig -> new RuntimeIssuerInfo(issuerConfig, loadResolver(issuerConfig)))
                                         .collect(Collectors.toConcurrentMap(info -> info.getConfig().getIssuer(), Function.identity()));
    }

    @Override
    public Key resolveSigningKey(JwsHeader header, Claims claims) {
        final RuntimeIssuerInfo loadedInfo = infoByIssuer.computeIfAbsent(claims.getIssuer(), issuer -> {
            throw new JwtException(format("Unrecognized issuer [%s]", claims.getIssuer()));
        });

        return loadedInfo.getResolver().resolve(loadedInfo.getConfig(), header);
    }

    private KeyResolver loadResolver(IssuerConfig issuerConfig) {
        JsonDefinedFactory<?, KeyResolver> factory = lookupFactory(beanFactory, issuerConfig.getKeySource().getBean());
        return factory.create(issuerConfig.getKeySource().getArgs());
    }
}
