package com.dnastack.gatekeeper.config;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.BeanFactory;

import java.util.Map;

import static java.lang.String.format;

/**
 * A base type for factories that load their config from JSON-like objects.
 *
 * @param <C> The type of configuration expected by a subclass
 * @param <T> The type of instance created by this factory
 */
public abstract class JsonDefinedFactory<C, T> {

    public static class ConfigException extends RuntimeException {
        public ConfigException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    protected final ObjectMapper objectMapper;
    private final Logger log;

    protected JsonDefinedFactory(ObjectMapper objectMapper, Logger log) {
        this.objectMapper = objectMapper;
        this.log = log;
    }

    /**
     * @return The type of this config, used for deserializing.
     */
    protected abstract TypeReference<C> getConfigType();

    /**
     * @param config The deserialized config (args section of config).
     * @return A fully configured instance from this factory.
     */
    protected abstract T create(C config);

    /**
     * @param config The config, parsed as map. Will be converted to a specific config type for this factory via Jackson.
     * @return A fully configured instance from this factory.
     */
    public T create(Map<String, ?> config) {
        C convertedConfig;
        try {
            convertedConfig = objectMapper.convertValue(config, getConfigType());
        } catch (RuntimeException e) {
            throw new ConfigException(format("Unable to parse into type [%s] from value [%s]", getConfigType().getType(), config), e);
        }

        log.info("Creating token enhancer from config [{}]", config);
        return create(convertedConfig);
    }

    public static <T> T createFactoryInstance(BeanFactory beanFactory, String beanName, Map<String, ?> args) {
        final JsonDefinedFactory<?, T> factory = lookupFactory(beanFactory, beanName);
        return factory.create(args);
    }

    @SuppressWarnings("unchecked")
    public static <T, F extends JsonDefinedFactory<?, T>> F lookupFactory(BeanFactory beanFactory, String factoryBeanName) throws BeansException {
        return (F) beanFactory.getBean(factoryBeanName, JsonDefinedFactory.class);
    }
}
