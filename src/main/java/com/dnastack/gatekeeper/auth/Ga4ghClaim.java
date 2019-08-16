package com.dnastack.gatekeeper.auth;

import lombok.Data;

@Data
public class Ga4ghClaim {
    private String value;
    private String source;
    private Long asserted;
    private Long expires;
    private String by;
}
