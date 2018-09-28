package com.dnastack.gatekeeper.auth;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

@Data
@ConfigurationProperties("inbound")
public class InboundEmailWhitelistConfiguration {
    private List<String> emailWhitelist;
}
