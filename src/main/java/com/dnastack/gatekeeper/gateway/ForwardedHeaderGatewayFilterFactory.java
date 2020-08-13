package com.dnastack.gatekeeper.gateway;

import com.dnastack.gatekeeper.util.XForwardUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.cloud.gateway.filter.headers.ForwardedHeadersFilter;
import org.springframework.cloud.gateway.filter.headers.XForwardedHeadersFilter;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.thymeleaf.util.StringUtils;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.springframework.cloud.gateway.filter.headers.ForwardedHeadersFilter.FORWARDED_HEADER;
import static org.springframework.cloud.gateway.support.GatewayToStringStyler.filterToStringCreator;

@Component
@Slf4j
public class ForwardedHeaderGatewayFilterFactory extends AbstractGatewayFilterFactory {

    public static final String X_FORWARDED_PROTO_HEADER = "X-Forwarded-Proto";

    @Autowired
    private ForwardedHeadersFilter filter;

    public GatewayFilter apply() {
        return apply(o -> {
        });
    }

    private void updateHeaders(ServerWebExchange exchange, HttpHeaders headers){
        // Set the forwarded header to be consistent with the URI, per the default behavior of
        // Spring Cloud Gateway's "ForwardedHeadersFilter".
        HttpHeaders newHeaders = filter.filter(exchange.getRequest().getHeaders(), exchange);
        headers.put(FORWARDED_HEADER, newHeaders.get(FORWARDED_HEADER));

        // Additionally, if X-forwarded-proto is set, overwrite the protocol in the forwarded header
        // with the value from X-forwarded-proto
        List<String> xFwdHeader = headers.get(X_FORWARDED_PROTO_HEADER);
        if(xFwdHeader != null){
            //if X-forwarded-proto header is present, set the forwarded header to use that protocol.
            String proto = xFwdHeader.get(0);
            log.debug("X-Forwarded-Proto is present, overwriting Forwarded: [proto=xxxx;...] with X-Forwarded-proto value [proto="+proto+";...]");
            if(proto != null){
                String currentFwdHeader = headers.get(FORWARDED_HEADER).get(0);
                String[] pairs = currentFwdHeader.split(";");
                List<String> pairList = Stream.of(pairs)
                      .map(pair->pair.startsWith("proto") ? "proto="+proto : pair)
                      .collect(Collectors.toList());

                headers.put(FORWARDED_HEADER, List.of(StringUtils.join(pairList, ";")));
            }
        }
    }

    @Override
    public GatewayFilter apply(Object config) {
        return new GatewayFilter() {
            @Override
            public Mono<Void> filter(ServerWebExchange exchange,
                                     GatewayFilterChain chain) {
                return chain.filter(exchange.mutate()
                                            .request(builder -> builder.headers(headers -> updateHeaders(exchange, headers)))
                                            .build());
            }

            @Override
            public String toString() {
                return filterToStringCreator(ForwardedHeaderGatewayFilterFactory.this)
                        .toString();
            }
        };
    }

}
