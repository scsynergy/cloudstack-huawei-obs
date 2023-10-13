// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.
package org.apache.cloudstack.utils;

import com.cloud.agent.AgentManager;
import com.cloud.agent.api.Answer;
import com.cloud.exception.InvalidParameterValueException;
import com.cloud.network.dao.NsxProviderDao;
import com.cloud.network.element.NsxProviderVO;
import org.apache.cloudstack.NsxAnswer;
import org.apache.cloudstack.agent.api.NsxCommand;
import org.apache.log4j.Logger;
import org.springframework.stereotype.Component;

import javax.inject.Inject;

import static java.util.Objects.isNull;

@Component
public class NsxControllerUtils {
    private static final Logger s_logger = Logger.getLogger(NsxControllerUtils.class);

    @Inject
    AgentManager agentMgr;
    @Inject
    NsxProviderDao nsxProviderDao;

    public NsxAnswer sendNsxCommand(NsxCommand cmd, long zoneId) throws IllegalArgumentException {

        NsxProviderVO nsxProviderVO = nsxProviderDao.findByZoneId(zoneId);
        if (nsxProviderVO == null) {
            s_logger.error("No NSX controller was found!");
            throw new InvalidParameterValueException("Failed to find an NSX controller");
        }
        Answer answer = agentMgr.easySend(nsxProviderVO.getHostId(), cmd);

        if (answer == null || !answer.getResult()) {
            s_logger.error("NSX API Command failed");
            throw new InvalidParameterValueException("Failed API call to NSX controller");
        }

        return (NsxAnswer) answer;
    }

    public static String getTier1GatewayName(String domainName, String accountName, String zoneName, String vpcName) {
        return String.format("%s-%s-%s-%s",  domainName, accountName, zoneName, vpcName);
    }

    public static String getNsxSegmentId(String domainName, String accountName, String zoneName, String vpcName, String tierNetworkName) {
        String segmentName = String.format("%s-%s-%s-",  domainName, accountName, zoneName);
        if (isNull(vpcName)) {
            return segmentName + tierNetworkName;
        }
        return segmentName + vpcName + "-" + tierNetworkName;
    }

    public static String getNsxDhcpRelayConfigId(String zoneName, String domainName, String accountName, String vpcName, String networkName) {
        String suffix = "-Relay";
        if (isNull(vpcName)) {
            return domainName + "-" + accountName + "-" + zoneName + "-" +networkName + suffix;
        }
        return String.format("%s-%s-%s-%s-%s%s", domainName, accountName, zoneName, vpcName, networkName, suffix);
    }
}