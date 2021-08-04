package com.dnastack.gatekeeper.gateway;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.event.FilterArgsEvent;
import org.springframework.cloud.gateway.filter.FilterDefinition;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.OrderedGatewayFilter;
import org.springframework.cloud.gateway.filter.factory.GatewayFilterFactory;
import org.springframework.cloud.gateway.support.ConfigurationService;
import org.springframework.cloud.gateway.support.ConfigurationUtils;
import org.springframework.core.Ordered;
import org.springframework.core.convert.ConversionService;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Component
@Slf4j
public class FilterDefinitionLoader {
    private final Map<String, GatewayFilterFactory> gatewayFilterFactories = new HashMap<>();
    private final BeanFactory beanFactory;
    private final ConversionService conversionService;
    private final ConfigurationService configurationService;

    @Autowired
    public FilterDefinitionLoader(List<GatewayFilterFactory> gatewayFilterFactories,
                                  ConversionService conversionService, ConfigurationService configurationService, BeanFactory beanFactory) {
        this.conversionService = conversionService;
        this.configurationService = configurationService;
        this.beanFactory = beanFactory;
        gatewayFilterFactories.forEach(factory -> this.gatewayFilterFactories.put(factory.name(), factory));
    }

    /**
     * Copied from {@link org.springframework.cloud.gateway.route.RouteDefinitionRouteLocator}. Converts
     * a list of filter definitions (as used in spring cloud gateway config dsl) into gateway filters.
     *
     * @param id The id of the route associated with given filter definitions. Used for error reporting and logging.
     * @param filterDefinitions A list of filter definitions pulled from gatekeeper specific route filter config.
     * @return A list of gateway filters corresponding to the given definitions.
     * @throws IllegalArgumentException when a {@link GatewayFilterFactory} cannot be resolved from a filter defintion.
     */
    @SuppressWarnings("unchecked")
    public List<GatewayFilter> loadFilters(String id, List<FilterDefinition> filterDefinitions) throws IllegalArgumentException {
        final SpelExpressionParser parser = new SpelExpressionParser();
        List<GatewayFilter> filters = filterDefinitions.stream()
                                                       .map(definition -> {
                                                           GatewayFilterFactory factory = this.gatewayFilterFactories.get(definition.getName());
                                                           if (factory == null) {
                                                               throw new IllegalArgumentException("Unable to find GatewayFilterFactory with name " + definition.getName());
                                                           }
                                                           Map<String, String> args = definition.getArgs();
                                                           if (log.isDebugEnabled()) {
                                                               log.debug("RouteDefinition " + id + " applying filter " + args + " to " + definition.getName());
                                                           }

                                                           Object configuration = this.configurationService.with(factory)
                                                               .name(definition.getName())
                                                               .properties(definition.getArgs())
                                                               .eventFunction((bound, properties) -> new FilterArgsEvent(this, id, (Map)properties))
                                                               .bind();

                                                           return factory.apply(configuration);
                                                       })
                                                       .collect(Collectors.toList());

        ArrayList<GatewayFilter> ordered = new ArrayList<>(filters.size());
        for (int i = 0; i < filters.size(); i++) {
            GatewayFilter gatewayFilter = filters.get(i);
            if (gatewayFilter instanceof Ordered) {
                ordered.add(gatewayFilter);
            }
            else {
                ordered.add(new OrderedGatewayFilter(gatewayFilter, i + 1));
            }
        }

        return ordered;
    }

}
