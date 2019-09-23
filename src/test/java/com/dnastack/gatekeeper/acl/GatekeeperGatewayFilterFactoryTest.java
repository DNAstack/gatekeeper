package com.dnastack.gatekeeper.acl;

import com.dnastack.gatekeeper.config.GatekeeperConfig;
import org.junit.Test;

import java.util.Map;

import static com.dnastack.gatekeeper.acl.GatekeeperGatewayFilterFactory.computeOutboundPath;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertThat;

public class GatekeeperGatewayFilterFactoryTest {

    @Test
    public void computePathReplacesSingleVariableWithTopLevelOutboundPath() {
        final GatekeeperConfig.Gateway config = new GatekeeperConfig.Gateway();
        config.setId("gatewayId");
        config.setOutbound(new GatekeeperConfig.OutboundRequest());
        config.getOutbound().setPath("foo/bar/{path}");

        final GatekeeperConfig.AccessControlItem accessControlItem = new GatekeeperConfig.AccessControlItem();
        accessControlItem.setId("accessItemId");

        final String path = computeOutboundPath(config, accessControlItem, Map.of("path", "banana/slam"));
        assertThat(path, equalTo("/foo/bar/banana/slam"));
    }

    @Test
    public void computePathReplacesWithEmptyVariableValue() {
        final GatekeeperConfig.Gateway config = new GatekeeperConfig.Gateway();
        config.setId("gatewayId");
        config.setOutbound(new GatekeeperConfig.OutboundRequest());
        config.getOutbound().setPath("{path}");

        final GatekeeperConfig.AccessControlItem accessControlItem = new GatekeeperConfig.AccessControlItem();
        accessControlItem.setId("accessItemId");

        final String path = computeOutboundPath(config, accessControlItem, Map.of("path", ""));
        assertThat(path, equalTo("/"));
    }
}