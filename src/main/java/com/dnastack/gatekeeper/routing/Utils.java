package com.dnastack.gatekeeper.routing;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.StringUtils;

import javax.servlet.http.HttpServletResponse;

@Slf4j
public class Utils {
    public static void setAccessDecision(HttpServletResponse response, String decision) {
        log.info("Access decision made: {}", decision);
        response.setHeader("X-Gatekeeper-Access-Decision", decision);
    }

    public static String publicPrefixOrAuthChallenge(String publicPrefix) throws UnroutableRequestException {
        if (StringUtils.isEmpty(publicPrefix)) {
            log.debug("Public prefix is empty. Sending 401 auth challenge.");
            throw new UnroutableRequestException(401, "Anonymous requests not accepted.");
        } else {
            return publicPrefix;
        }
    }
}
