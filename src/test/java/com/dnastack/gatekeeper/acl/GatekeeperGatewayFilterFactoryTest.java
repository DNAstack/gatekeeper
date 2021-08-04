package com.dnastack.gatekeeper.acl;

import com.dnastack.gatekeeper.config.GatekeeperConfig;
import org.junit.Test;

import java.util.List;
import java.util.Map;

import static com.dnastack.gatekeeper.acl.GatekeeperGatewayFilterFactory.computeOutboundPath;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;

public class GatekeeperGatewayFilterFactoryTest {

    @Test
    public void computePathReplacesSingleVariableOutboundPath() {
        final GatekeeperConfig.Gateway config = new GatekeeperConfig.Gateway();
        config.setId("gatewayId");

        final GatekeeperConfig.AccessControlItem accessControlItem = new GatekeeperConfig.AccessControlItem();
        accessControlItem.setId("accessItemId");
        accessControlItem.setOutbound(new GatekeeperConfig.OutboundRequestConfig());
        accessControlItem.getOutbound().setPath("foo/bar/{path}");

        final String path = computeOutboundPath(config, accessControlItem, Map.of("path", "banana/slam"));
        assertEquals(path, "/foo/bar/banana/slam");
    }

    @Test
    public void computePathReplacesWithEmptyVariableValue() {
        final GatekeeperConfig.Gateway config = new GatekeeperConfig.Gateway();
        config.setId("gatewayId");

        final GatekeeperConfig.AccessControlItem accessControlItem = new GatekeeperConfig.AccessControlItem();
        accessControlItem.setId("accessItemId");
        accessControlItem.setOutbound(new GatekeeperConfig.OutboundRequestConfig());
        accessControlItem.getOutbound().setPath("{path}");

        final String path = computeOutboundPath(config, accessControlItem, Map.of("path", ""));
        assertEquals(path, "/");
    }
}
