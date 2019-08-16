package com.dnastack.gatekeeper.auth;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;

import java.util.Map;

import static java.lang.String.format;

/**
 * @param <T> GrantConfig type.
 */
@Slf4j
public abstract class TokenAuthorizerFactory<T> {

    public static class ConfigException extends RuntimeException {
        public ConfigException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    protected final ObjectMapper objectMapper;

    protected TokenAuthorizerFactory(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    /**
     * @return The type of this config, used for deserializing.
     */
    protected abstract TypeReference<T> getConfigType();

    /**
     * @param config The deserialized config (args section of token authorizer config).
     * @return A fully configured token enhancer.
     */
    protected abstract TokenAuthorizer create(T config);

    /**
     * @param config The config, parsed as map. Will be converted to a specific config type for this factory via Jackson.
     * @return A fully configured token enhancer.
     */
    public TokenAuthorizer create(Map<String, ?> config) {
        T convertedConfig;
        try {
            convertedConfig = objectMapper.convertValue(config, getConfigType());
        } catch (RuntimeException e) {
            throw new ConfigException(format("Unable to parse into type [%s] from value [%s]", getConfigType().getType(), config), e);
        }

        log.info("Creating token enhancer from config [{}]", config);
        return create(convertedConfig);
    }

}
