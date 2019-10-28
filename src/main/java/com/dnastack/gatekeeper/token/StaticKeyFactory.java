package com.dnastack.gatekeeper.token;

import com.dnastack.gatekeeper.config.JsonDefinedFactory;
import com.dnastack.gatekeeper.config.RsaKeyHelper;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Slf4j
@Component("static-key")
public class StaticKeyFactory extends JsonDefinedFactory<StaticKeyFactory.Config, ConfiguredSigningKeyResolver.KeyResolver> {

    @Autowired
    public StaticKeyFactory(ObjectMapper objectMapper) {
        super(objectMapper, log);
    }

    @Override
    protected TypeReference<Config> getConfigType() {
        return new TypeReference<>() {};
    }

    @Override
    protected ConfiguredSigningKeyResolver.KeyResolver create(Config config) {
        return (issuerConfig, header) -> RsaKeyHelper.parsePublicKey(config.getPublicKey());
    }

    @Data
    public static class Config {
        @JsonProperty("public-key")
        private String publicKey;
    }
}
