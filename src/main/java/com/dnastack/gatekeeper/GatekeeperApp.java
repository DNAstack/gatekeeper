package com.dnastack.gatekeeper;

import com.dnastack.gatekeeper.auth.InboundEmailWhitelistConfiguration;
import com.dnastack.gatekeeper.auth.InboundKeyConfiguration;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.netflix.zuul.EnableZuulProxy;

@SpringBootApplication
@EnableZuulProxy
@EnableConfigurationProperties({InboundKeyConfiguration.class, InboundEmailWhitelistConfiguration.class})
public class GatekeeperApp {

    public static void main(String[] args) {
        SpringApplication.run(GatekeeperApp.class, args);
    }
}
