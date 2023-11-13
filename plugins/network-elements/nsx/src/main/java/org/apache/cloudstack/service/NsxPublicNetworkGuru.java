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
package org.apache.cloudstack.service;

import com.cloud.dc.VlanDetailsVO;
import com.cloud.dc.dao.VlanDetailsDao;
import com.cloud.deploy.DeploymentPlan;
import com.cloud.exception.ConcurrentOperationException;
import com.cloud.exception.InsufficientAddressCapacityException;
import com.cloud.exception.InsufficientVirtualNetworkCapacityException;
import com.cloud.network.Network;
import com.cloud.network.Networks;
import com.cloud.network.nsx.NsxService;
import com.cloud.network.dao.IPAddressVO;
import com.cloud.network.dao.NetworkVO;
import com.cloud.network.guru.PublicNetworkGuru;
import com.cloud.network.vpc.VpcOffering;
import com.cloud.network.vpc.VpcVO;
import com.cloud.network.vpc.dao.VpcDao;
import com.cloud.network.vpc.dao.VpcOfferingDao;
import com.cloud.network.vpc.dao.VpcOfferingServiceMapDao;
import com.cloud.offering.NetworkOffering;
import com.cloud.offerings.dao.NetworkOfferingDao;
import com.cloud.user.Account;
import com.cloud.utils.exception.CloudRuntimeException;
import com.cloud.vm.NicProfile;
import com.cloud.vm.VirtualMachineProfile;
import org.apache.cloudstack.NsxAnswer;
import org.apache.cloudstack.agent.api.CreateOrUpdateNsxTier1NatRuleCommand;
import org.apache.cloudstack.api.ApiConstants;
import org.apache.cloudstack.utils.NsxControllerUtils;
import org.apache.cloudstack.utils.NsxHelper;
import org.apache.commons.collections.CollectionUtils;
import org.apache.log4j.Logger;

import javax.inject.Inject;
import java.util.List;
import java.util.stream.Collectors;

public class NsxPublicNetworkGuru extends PublicNetworkGuru {

    @Inject
    private VlanDetailsDao vlanDetailsDao;
    @Inject
    private VpcDao vpcDao;
    @Inject
    private VpcOfferingServiceMapDao vpcOfferingServiceMapDao;
    @Inject
    private NsxControllerUtils nsxControllerUtils;
    @Inject
    private NsxService nsxService;
    @Inject
    private VpcOfferingDao vpcOfferingDao;
    @Inject
    private NetworkOfferingDao offeringDao;

    private static final Logger s_logger = Logger.getLogger(NsxPublicNetworkGuru.class);

    public NsxPublicNetworkGuru() {
        super();
    }

    protected boolean canHandle(NetworkOffering offering) {
        return isMyTrafficType(offering.getTrafficType()) && offering.isSystemOnly() && offering.isForNsx();
    }

    @Override
    public Network design(NetworkOffering offering, DeploymentPlan plan, Network network, String name, Long vpcId, Account owner) {
        if (!canHandle(offering)) {
            return null;
        }

        if (offering.getTrafficType() == Networks.TrafficType.Public) {
            NetworkVO ntwk =
                    new NetworkVO(offering.getTrafficType(), Networks.Mode.Static, network.getBroadcastDomainType(), offering.getId(), Network.State.Setup, plan.getDataCenterId(),
                            plan.getPhysicalNetworkId(), offering.isRedundantRouter());
            return ntwk;
        } else {
            return null;
        }
    }

    @Override
    public NicProfile allocate(Network network, NicProfile nic, VirtualMachineProfile vm) throws InsufficientVirtualNetworkCapacityException, InsufficientAddressCapacityException, ConcurrentOperationException {
        s_logger.debug("NSX Public network guru: allocate");
        // NicProfile createdProfile = super.allocate(network, nic, vm);

        IPAddressVO ipAddress = _ipAddressDao.findByIp(nic.getIPv4Address());
        if (ipAddress == null) {
            String err = String.format("Cannot find the IP address %s", nic.getIPv4Address());
            s_logger.error(err);
            throw new CloudRuntimeException(err);
        }
        Long vpcId = ipAddress.getVpcId();
        if (vpcId == null) {
            // TODO: Pass network.getId() to support isolated networks
            throw new CloudRuntimeException("TODO: Add support for isolated networks public network");
        }
        VpcVO vpc = vpcDao.findById(vpcId);
        if (vpc == null) {
            String err = String.format("Cannot find a VPC with ID %s", vpcId);
            s_logger.error(err);
            throw new CloudRuntimeException(err);
        }

        // For NSX, use VR Public IP != Source NAT
        List<IPAddressVO> ips = _ipAddressDao.listByAssociatedVpc(vpcId, true);
        if (CollectionUtils.isEmpty(ips)) {
            String err = String.format("Cannot find a source NAT IP for the VPC %s", vpc.getName());
            s_logger.error(err);
            throw new CloudRuntimeException(err);
        }
        ips = ips.stream().filter(x -> !x.getAddress().addr().equals(nic.getIPv4Address())).collect(Collectors.toList());
        // Use Source NAT IP address from the NSX Public Range. Do not Use the VR Public IP address
        ipAddress = ips.get(0);
        if (ipAddress.isSourceNat() && !ipAddress.isForSystemVms()) {
            VlanDetailsVO detail = vlanDetailsDao.findDetail(ipAddress.getVlanId(), ApiConstants.NSX_DETAIL_KEY);
            if (detail != null && detail.getValue().equalsIgnoreCase("true")) {
                long accountId = vpc.getAccountId();
                long domainId = vpc.getDomainId();
                long dataCenterId = vpc.getZoneId();
                boolean isForVpc = true;
                long resourceId = isForVpc ? vpc.getId() : network.getId();
                Network.Service[] services = {Network.Service.SourceNat};
                boolean sourceNatEnabled = vpcOfferingServiceMapDao.areServicesSupportedByVpcOffering(vpc.getVpcOfferingId(), services);

                s_logger.info(String.format("Creating Tier 1 Gateway for VPC %s", vpc.getName()));
                boolean result = nsxService.createVpcNetwork(dataCenterId, accountId, domainId, resourceId, vpc.getName(), sourceNatEnabled);
                if (!result) {
                    String msg = String.format("Error creating Tier 1 Gateway for VPC %s", vpc.getName());
                    s_logger.error(msg);
                    throw new CloudRuntimeException(msg);
                }

                boolean hasNatSupport = false;
                if (vpc == null) {
                    NetworkOffering offering = offeringDao.findById(network.getNetworkOfferingId());
                    hasNatSupport = NetworkOffering.NsxMode.NATTED.name().equals(offering.getNsxMode());
                } else {
                    VpcOffering vpcOffering = vpcOfferingDao.findById(vpc.getVpcOfferingId());
                    hasNatSupport = NetworkOffering.NsxMode.NATTED.name().equals(vpcOffering.getNsxMode());
                }

                if (hasNatSupport) {
                    String tier1GatewayName = NsxControllerUtils.getTier1GatewayName(domainId, accountId, dataCenterId, resourceId, isForVpc);
                    String translatedIp = ipAddress.getAddress().addr();
                    s_logger.debug(String.format("Creating NSX Nat Rule for Tier1 GW %s for translated IP %s", tier1GatewayName, translatedIp));
                    String natRuleId = NsxControllerUtils.getNsxNatRuleId(domainId, accountId, dataCenterId, resourceId, isForVpc);
                    CreateOrUpdateNsxTier1NatRuleCommand cmd = NsxHelper.createOrUpdateNsxNatRuleCommand(domainId, accountId, dataCenterId, tier1GatewayName, "SNAT", translatedIp, natRuleId);
                    NsxAnswer nsxAnswer = nsxControllerUtils.sendNsxCommand(cmd, dataCenterId);
                    if (!nsxAnswer.getResult()) {
                        String msg = String.format("Could not create NSX Nat Rule on Tier1 Gateway %s for IP %s", tier1GatewayName, translatedIp);
                        s_logger.error(msg);
                        throw new CloudRuntimeException(msg);
                    }
                }
            }
        }
        return nic;
    }
}
