package com.dnastack.gatekeeper.routing;

import com.dnastack.gatekeeper.acl.GatekeeperGatewayFilterFactory;
import com.dnastack.gatekeeper.config.GatekeeperConfig;
import com.dnastack.gatekeeper.gateway.AddBasicAuthHeaderGatewayFilterFactory;
import com.dnastack.gatekeeper.gateway.PrependUriPathGatewayFilterFactory;
import com.dnastack.gatekeeper.gateway.StripAuthHeaderGatewayFilterFactory;
import com.dnastack.gatekeeper.logging.LoggingGatewayFilterFactory;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.net.URI;

@Slf4j
@Configuration
public class AclRouter {

    private final GatekeeperConfig config;

    @Autowired
    public AclRouter(GatekeeperConfig config) {
        this.config = config;
    }

    @Bean
    public RouteLocator aclRouteLocator(RouteLocatorBuilder builder,
                                        GatekeeperGatewayFilterFactory gatekeeperGatewayFilterFactory,
                                        PrependUriPathGatewayFilterFactory prependUriPathGatewayFilterFactory,
                                        StripAuthHeaderGatewayFilterFactory stripAuthHeaderGatewayFilterFactory,
                                        AddBasicAuthHeaderGatewayFilterFactory addBasicAuthHeaderGatewayFilterFactory,
                                        LoggingGatewayFilterFactory loggingGatewayFilterFactory) {
        final GatewayFilter stripAuthHeaderFilter = stripAuthHeaderGatewayFilterFactory.apply(new Object());
        final GatewayFilter loggingFilter = loggingGatewayFilterFactory.apply();

        RouteLocatorBuilder.Builder routes = builder.routes();

        for (GatekeeperConfig.Gateway gateway : config.getGateways()) {
            final GatewayFilter prependUriFilter = prependUriPathGatewayFilterFactory.apply(gateway.getOutbound().getUrl());
            final GatekeeperConfig.OutboundAuthorization authorization = gateway.getOutbound().getAuthorization();
            final String username = authorization.getUsername();
            final String password = authorization.getPassword();
            final GatewayFilter basicAuthFilter = addBasicAuthHeaderGatewayFilterFactory.apply(username, password);

            final GatewayFilter gatekeeperFilter = gatekeeperGatewayFilterFactory.apply(gateway);
            routes = routes.route(gateway.getId(),
                                  r -> r.path(gateway.getInbound().getPath())
                                        .filters(f -> f.filter(gatekeeperFilter)
                                                       .filter(prependUriFilter)
                                                       .filter(stripAuthHeaderFilter)
                                                       .filter(basicAuthFilter)
                                                       .filter(loggingFilter))
                                        .uri(gateway.getOutbound().getUrl()));
        }

        return routes.build();
    }
}
