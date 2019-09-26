package com.dnastack.gatekeeper.routing;

import com.dnastack.gatekeeper.acl.GatekeeperGatewayFilterFactory;
import com.dnastack.gatekeeper.config.GatekeeperConfig;
import com.dnastack.gatekeeper.config.JsonDefinedFactory;
import com.dnastack.gatekeeper.gateway.FilterDefinitionLoader;
import com.dnastack.gatekeeper.gateway.PrependUriPathGatewayFilterFactory;
import com.dnastack.gatekeeper.gateway.StripAuthHeaderGatewayFilterFactory;
import com.dnastack.gatekeeper.logging.LoggingGatewayFilterFactory;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static com.dnastack.gatekeeper.config.JsonDefinedFactory.lookupFactory;

@Slf4j
@Configuration
@RestController
public class AclRouter {

    private final GatekeeperConfig config;
    private final FilterDefinitionLoader filterDefinitionLoader;
    private BeanFactory beanFactory;

    @Autowired
    public AclRouter(GatekeeperConfig config, FilterDefinitionLoader filterDefinitionLoader, BeanFactory beanFactory) {
        this.config = config;
        this.filterDefinitionLoader = filterDefinitionLoader;
        this.beanFactory = beanFactory;
    }

    @Bean
    public RouteLocator aclRouteLocator(RouteLocatorBuilder builder,
                                        GatekeeperGatewayFilterFactory gatekeeperGatewayFilterFactory,
                                        PrependUriPathGatewayFilterFactory prependUriPathGatewayFilterFactory,
                                        StripAuthHeaderGatewayFilterFactory stripAuthHeaderGatewayFilterFactory,
                                        LoggingGatewayFilterFactory loggingGatewayFilterFactory) {
        final GatewayFilter stripAuthHeaderFilter = stripAuthHeaderGatewayFilterFactory.apply(new Object());
        final GatewayFilter loggingFilter = loggingGatewayFilterFactory.apply();

        RouteLocatorBuilder.Builder routes = builder.routes();

        for (GatekeeperConfig.Gateway gateway : config.getGateways()) {
            final GatewayFilter prependUriFilter = prependUriPathGatewayFilterFactory.apply(gateway.getOutbound().getBaseUrl());

            final GatekeeperConfig.OutboundAuthentication outboundAuthentication = gateway.getOutbound().getAuthentication();
            final String authenticatorName = Optional.ofNullable(outboundAuthentication)
                                                     .map(GatekeeperConfig.OutboundAuthentication::getMethod)
                                                     .orElse("noop-client-authenticator");
            final JsonDefinedFactory<?, GatewayFilter> clientAuthenticatorFactory = lookupFactory(beanFactory, authenticatorName);
            final Map<String, Object> args = Optional.ofNullable(outboundAuthentication)
                                                     .map(GatekeeperConfig.OutboundAuthentication::getArgs)
                                                     .orElseGet(Map::of);
            final GatewayFilter outboundAuthFilter = clientAuthenticatorFactory.create(args);

            final GatewayFilter gatekeeperFilter = gatekeeperGatewayFilterFactory.apply(gateway);
            final List<GatewayFilter> customFilters = filterDefinitionLoader.loadFilters(gateway.getId(), gateway.getOutbound().getFilters());
            routes = routes.route(gateway.getId(),
                                  r -> r.path(gateway.getInbound().getPath())
                                        .filters(f -> f.filter(gatekeeperFilter)
                                                       .filter(prependUriFilter)
                                                       .filter(stripAuthHeaderFilter)
                                                       .filter(outboundAuthFilter)
                                                       .filters(customFilters)
                                                       .filter(loggingFilter))
                                        .uri(gateway.getOutbound().getBaseUrl()));
        }

        return routes.build();
    }

}
