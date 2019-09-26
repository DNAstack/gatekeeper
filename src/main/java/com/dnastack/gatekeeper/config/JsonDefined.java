package com.dnastack.gatekeeper.config;

import java.util.Map;

public interface JsonDefined {
    String getMethod();
    Map<String, Object> getArgs();
}
