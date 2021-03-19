package com.dnastack.gatekeeper.token;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import javax.validation.constraints.NotEmpty;
import java.util.List;

@Configuration
@ConfigurationProperties(prefix = "gatekeeper.token")
@Data
public class TokenConfig {
    @NotEmpty
    private List<String> audiences;
}
