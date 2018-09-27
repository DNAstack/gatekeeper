package com.dnastack.gatekeeper;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Data
@ConfigurationProperties("inbound.jwt")
public class InboundKeyConfiguration {

    private String algorithm;
    private String publicKey;

}
