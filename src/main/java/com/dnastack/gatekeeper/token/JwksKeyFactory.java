package com.dnastack.gatekeeper.token;

import com.dnastack.gatekeeper.config.InboundConfiguration;
import com.dnastack.gatekeeper.config.JsonDefinedFactory;
import com.dnastack.gatekeeper.config.RsaKeyHelper;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import feign.Feign;
import feign.RequestLine;
import feign.jackson.JacksonDecoder;
import feign.jackson.JacksonEncoder;
import io.jsonwebtoken.JwtException;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.math.BigInteger;
import java.net.URI;
import java.security.Key;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import static java.lang.String.format;

@Slf4j
@Component("oidc-jwks")
public class JwksKeyFactory extends JsonDefinedFactory<JwksKeyFactory.Config, ConfiguredSigningKeyResolver.KeyResolver> {

    private final JwksKeyResolver keyResolver;

    @Autowired
    public JwksKeyFactory(ObjectMapper objectMapper) {
        super(objectMapper, log);
        keyResolver = new JwksKeyResolver(objectMapper);
    }

    @Override
    protected TypeReference<Config> getConfigType() {
        return new TypeReference<>() {};
    }

    @Override
    protected ConfiguredSigningKeyResolver.KeyResolver create(Config config) {
        return new JwksKeyResolver(objectMapper);
    }

    @Data
    public static class Config {
    }

    private static class JwksKeyResolver implements ConfiguredSigningKeyResolver.KeyResolver {
        private final ConcurrentMap<String, Key> keysByIssuer = new ConcurrentHashMap<>();
        private final ObjectMapper objectMapper;

        private JwksKeyResolver(ObjectMapper objectMapper) {
            this.objectMapper = objectMapper;
        }

        @Override
        public Key resolve(InboundConfiguration.IssuerConfig issuerConfig, String givenKeyId) {
            final String issuer = issuerConfig.getIssuer();
            final OidcClient oidcClient = Feign.builder()
                                               .encoder(new JacksonEncoder(objectMapper))
                                               .decoder(new JacksonDecoder(objectMapper))
                                               .target(OidcClient.class, issuer);
            return keysByIssuer.computeIfAbsent(issuerConfig.getIssuer(), key -> {
                final OidcConfiguration oidcConfig = oidcClient.getConfiguration();
                final String jwksUri = oidcConfig.getJwksUri();
                final Jwks jwks = oidcClient.getJwks(URI.create(jwksUri));

                final RsaJwk foundJwk;
                if (givenKeyId != null) {
                    foundJwk = jwks.getKeys()
                                   .stream()
                                   .filter(jwk -> Objects.equals(givenKeyId, jwk.getKeyId()))
                                   .findFirst()
                                   .orElseThrow(() -> new JwtException(format("No key from issuer [%s] found for key ID [%s]", issuer, givenKeyId)));
                } else if (jwks.getKeys().size() == 1) {
                    foundJwk = jwks.getKeys().get(0);
                } else {
                    throw new JwtException(format("ambiguous key: token from issuer [%s] has no kid and JWKS endpoint contains multiple keys", issuer));
                }

                final Base64.Decoder decoder = Base64.getUrlDecoder();
                final BigInteger modulus = new BigInteger(1, decoder.decode(foundJwk.getModulus()));
                final BigInteger publicExponent = new BigInteger(1, decoder.decode(foundJwk.getExponent()));

                return RsaKeyHelper.createPublicKey(modulus, publicExponent);
            });
        }

    }

    @Data
    public static class OidcConfiguration {
        @JsonProperty("jwks_uri")
        private String jwksUri;
    }

    @Data
    public static class Jwks {
        private List<RsaJwk> keys;
    }

    @Data
    public static class RsaJwk {
        @JsonProperty("kty")
        private String keyType;

        @JsonProperty("alg")
        private String algorithm;

        private String use;

        @JsonProperty("kid")
        private String keyId;

        @JsonProperty("e")
        private String exponent;

        @JsonProperty("n")
        private String modulus;
    }

    public interface OidcClient {
        @RequestLine("GET /.well-known/openid-configuration")
        OidcConfiguration getConfiguration();

        @RequestLine("GET {uri}")
        Jwks getJwks(URI uri);
    }
}
