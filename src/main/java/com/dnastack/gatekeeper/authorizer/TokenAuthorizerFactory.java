package com.dnastack.gatekeeper.authorizer;

import com.dnastack.gatekeeper.config.TokenAuthorizationConfig;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.BeanFactory;

import java.util.Map;

import static java.lang.String.format;

/**
 * @param <T> GrantConfig type.
 */
public abstract class TokenAuthorizerFactory<T> {

    public static class ConfigException extends RuntimeException {
        public ConfigException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    protected final ObjectMapper objectMapper;
    private final Logger log;

    protected TokenAuthorizerFactory(ObjectMapper objectMapper, Logger log) {
        this.objectMapper = objectMapper;
        this.log = log;
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

    public static TokenAuthorizer createTokenAuthorizer(BeanFactory beanFactory, TokenAuthorizationConfig config) throws BeansException {
        final TokenAuthorizerFactory<?> factory = beanFactory.getBean(config.getMethod(), TokenAuthorizerFactory.class);
        return factory.create(config.getArgs());
    }

}
