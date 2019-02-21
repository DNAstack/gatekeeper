package com.dnastack.gatekeeper;

import com.dnastack.gatekeeper.config.InboundEmailWhitelistConfiguration;
import com.dnastack.gatekeeper.config.InboundKeyConfiguration;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties({InboundKeyConfiguration.class, InboundEmailWhitelistConfiguration.class})
public class GatekeeperApp {

    public static void main(String[] args) {
        SpringApplication.run(GatekeeperApp.class, args);
    }
}
