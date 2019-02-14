package com.dnastack.gatekeeper.routing;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.RouterFunctions;
import org.springframework.web.reactive.function.server.ServerResponse;

import static org.springframework.http.MediaType.TEXT_HTML;
import static org.springframework.web.reactive.function.server.RequestPredicates.GET;
import static org.springframework.web.reactive.function.server.ServerResponse.ok;

@Configuration
public class IndexRouter {

    @Value("classpath:/static/index.html")
    private Resource index;

    @Bean
    RouterFunction<ServerResponse> index() {
        return RouterFunctions.route(GET("/"),
                                     request -> ok()
                                             .contentType(TEXT_HTML)
                                             .syncBody(index));
    }
}
