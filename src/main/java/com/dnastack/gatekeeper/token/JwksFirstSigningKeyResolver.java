package com.dnastack.gatekeeper.token;

import com.dnastack.gatekeeper.config.InboundConfiguration.IssuerConfig;
import com.dnastack.gatekeeper.config.RsaKeyHelper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.SigningKeyResolverAdapter;
import lombok.Value;

import java.security.Key;
import java.security.PublicKey;
import java.util.Collection;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.stream.Collectors;

import static java.lang.String.format;
import static java.util.Collections.unmodifiableMap;

public class JwksFirstSigningKeyResolver extends SigningKeyResolverAdapter {

    @Value
    static class RuntimeIssuerInfo {
        IssuerConfig config;
        Key loadedKey;
    }

    private final ConcurrentMap<String, RuntimeIssuerInfo> infoByIssuer;

    public JwksFirstSigningKeyResolver(Collection<IssuerConfig> issuerConfigs) {
        infoByIssuer = issuerConfigs.stream()
                                    .collect(Collectors.toConcurrentMap(IssuerConfig::getIssuer, config -> new RuntimeIssuerInfo(config, null)));
    }

    @Override
    public Key resolveSigningKey(JwsHeader header, Claims claims) {
        final RuntimeIssuerInfo loadedInfo = infoByIssuer.compute(claims.getIssuer(), (issuer, currentInfo) -> {
            if (currentInfo == null) {
                throw new JwtException(format("Unrecognized issuer [%s]", claims.getIssuer()));
            } else if (currentInfo.getLoadedKey() != null) {
                return currentInfo;
            } else {
                final Key loadedKey = loadKey(currentInfo.getConfig());
                return new RuntimeIssuerInfo(currentInfo.getConfig(), loadedKey);
            }
        });

        return loadedInfo.getLoadedKey();
    }

    private Key loadKey(IssuerConfig issuerConfig) {
        if (issuerConfig.getAlgorithm().toLowerCase().startsWith("rs")) {
            final PublicKey publicKey = RsaKeyHelper.parsePublicKey(issuerConfig.getPublicKey());
            return publicKey;
        } else {
            throw new IllegalArgumentException(format("Only RS* algorithms supported in gatekeeper: Given algorithm [%s]", issuerConfig.getAlgorithm()));
        }
    }
}
