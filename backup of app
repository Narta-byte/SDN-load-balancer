/*
 * Copyright 2016 Open Networking Laboratory
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.student.lb;

import org.apache.felix.scr.annotations.*;
import org.onlab.packet.*;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.Host;
import org.onosproject.net.PortNumber;
import org.onosproject.net.flow.*;
import org.onosproject.net.flowobjective.DefaultForwardingObjective;
import org.onosproject.net.flowobjective.FlowObjectiveService;
import org.onosproject.net.flowobjective.ForwardingObjective;
import org.onosproject.net.host.HostService;
import org.onosproject.net.packet.*;
import org.slf4j.Logger;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List; 
import java.util.concurrent.ConcurrentHashMap;


import static org.slf4j.LoggerFactory.getLogger;


@Component(immediate = true)
public class AppComponent {

    private final Logger log = getLogger(getClass());

    ConcurrentHashMap<MacAddress, Ip4Address> hostTable = new ConcurrentHashMap<>();
    ConcurrentHashMap<MacAddress, Ip4Address> serverTable = new ConcurrentHashMap<>();
    ConcurrentHashMap<Ip4Address, MacAddress> mappedServerTable = new ConcurrentHashMap<>();

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected FlowObjectiveService flowObjectiveService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected HostService hostService;

    private ReactivePacketProcessor processor = new ReactivePacketProcessor();
    private int requestsServed = 0;
    private ApplicationId appId;
    @Activate
    protected void activate() {
        appId = coreService.registerApplication("org.student.lb");
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_IPV4);
        packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);
        packetService.addProcessor(processor, PacketProcessor.director(2));
        log.info("Started", appId.id());
    }

    @Deactivate
    protected void deactivate() {
        flowRuleService.removeFlowRulesById(appId);
        packetService.removeProcessor(processor);
        processor = null;
        log.info("Stopped");
    }

    /**
     * Our custom Packet Processor, which overrides the default  process() function.
     */
    private class ReactivePacketProcessor implements PacketProcessor {

        @Override
        public void process(PacketContext context) {
            InboundPacket pkt = context.inPacket();
            Ethernet ethPkt = pkt.parsed();
            
            String lb_mac= "00:00:00:00:00:14";
            String lb_ip = "10.0.0.100";

            //TODO HARDCODE SERVERS
            serverTable.put(MacAddress.valueOf("00:00:00:00:00:02"),Ip4Address.valueOf("10.0.0.2"));
            serverTable.put(MacAddress.valueOf("00:00:00:00:00:03"),Ip4Address.valueOf("10.0.0.3"));

            //Discard if  packet is null.
            if (ethPkt == null) {
                return;
            }
            
            /*First step is to handle the ARP requests.
            For that catch all ARP packets and construct and send back the ARP replies.
            */
            if (ethPkt.getEtherType() == Ethernet.TYPE_ARP) {
                log.info("ARP request received");
                ARP arpPacket = (ARP) ethPkt.getPayload();
                //Create an ARP reply packet with the LB's MAC:IP
                Ethernet arpReply;
                if (hostTable.containsKey(ethPkt.getSourceMAC())) {
                    log.info("The HOST has sent an arp with this address {}", ethPkt.getSourceMAC().toString());
                    log.info("Sending ARP reply to with LB IP {}",Ip4Address.valueOf(lb_ip).toString());
                    log.info("Sending ARP reply to with LB MAC {}",MacAddress.valueOf(lb_mac).toString());
                    arpReply = arpPacket.buildArpReply(Ip4Address.valueOf(lb_ip), MacAddress.valueOf(lb_mac), ethPkt);
                } else if (serverTable.containsKey(ethPkt.getSourceMAC())) {
                    // Husk at mappe ARP nede i ipv4 delen
                    log.info("Server is sending ARP request with this MACaddress {}",ethPkt.getSourceMAC().toString());
                    log.info("Sending ARP reply to with HOST IP {}",pkt.receivedFrom().ipElementId().ipAddress().getIp4Address().toString());
                    log.info("Sending ARP reply to with HOST MAC {}",mappedServerTable.get(pkt.receivedFrom().ipElementId().ipAddress().getIp4Address()).toString());
                    arpReply = arpPacket.buildArpReply(pkt.receivedFrom().ipElementId().ipAddress().getIp4Address(), mappedServerTable.get(pkt.receivedFrom().ipElementId().ipAddress().getIp4Address()),ethPkt);
                    
                } else {
                    //log.info("HOST has ARP requested, with this MACaddress {}", ethPkt.getSourceMAC().toString());
                    //log.info("Adding them to map of hosts, and this is their IP {}", pkt.receivedFrom().ipElementId().ipAddress().getIp4Address().toString());
                    

                    hostTable.put(ethPkt.getSourceMAC(),pkt.receivedFrom().ipElementId().ipAddress().getIp4Address());
                    arpReply = arpPacket.buildArpReply(Ip4Address.valueOf(lb_ip), MacAddress.valueOf(lb_mac), ethPkt);
                }
                //Send the ARP reply back to the host.
                log.info("ARP reply to {}", ethPkt.getSourceMAC().toString());
                for (Host host : hostService.getHostsByMac(ethPkt.getSourceMAC())) {
                    TrafficTreatment trafficTreatment = DefaultTrafficTreatment.builder().setOutput(host.location().port()).build();
                    ByteBuffer byteBuffer = ByteBuffer.wrap(arpReply.serialize());
                    OutboundPacket outboundPacket = new DefaultOutboundPacket(host.location().deviceId(),trafficTreatment,byteBuffer);
                    packetService.emit(outboundPacket);
                }
                return;
            }
            // From here on we handle only IPv4 packets.
            if (ethPkt.getEtherType() != Ethernet.TYPE_IPV4) return;
            IPv4 ipv4Packet = (IPv4) ethPkt.getPayload();
            int srcPort, dstPort = 0;

            //Create the Traffic Selector and start adding criteria.
            TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
            selector.matchEthType(Ethernet.TYPE_IPV4);

            //Handle TCP packets here.
            if (ipv4Packet.getProtocol() == IPv4.PROTOCOL_TCP) {
                TCP tcpPkt = (TCP) ipv4Packet.getPayload();
                srcPort = tcpPkt.getSourcePort();
                dstPort = tcpPkt.getDestinationPort();
                //Very important here: Specify the protocol (TCP, UDP) before specifying transport port.
                //Specifying only the transport port WILL NOT work.
                selector.matchIPProtocol(IPv4.PROTOCOL_TCP).matchTcpSrc(TpPort.tpPort(srcPort))
                        .matchTcpDst(TpPort.tpPort(dstPort));
            }
            //Handle UPD packets here.
            else if (ipv4Packet.getProtocol() == IPv4.PROTOCOL_UDP) {
                UDP udpPkt = (UDP) ipv4Packet.getPayload();
                srcPort = udpPkt.getSourcePort();
                dstPort = udpPkt.getDestinationPort();
                selector.matchIPProtocol(IPv4.PROTOCOL_UDP).matchUdpSrc(TpPort.tpPort(srcPort))
                        .matchUdpDst(TpPort.tpPort(dstPort));
            }
            selector.matchIPDst(IpPrefix.valueOf(IpAddress.valueOf(lb_ip), IpPrefix.MAX_INET_MASK_LENGTH));

            // In order to LB the traffic use the number of requests so far as a criterion. Before finishing the processing block() the context.
            // The port is used as a matching criterion in the configuration of the Traffic selector (above) !
            if (requestsServed % 2 == 0) {
                // Forward to H2
                // HUSK HOSTEN HER PLZ
                mappedServerTable.put((Ip4Address) IpAddress.valueOf(ipv4Packet.getSourceAddress()), ethPkt.getSourceMAC());

                forwardRequest(context, MacAddress.valueOf("00:00:00:00:00:02"),ethPkt.getSourceMAC(),
                IpAddress.valueOf("10.0.0.2"),IpAddress.valueOf(ipv4Packet.getSourceAddress()), 2, selector.build());
                log.info("Request will be forwarded to H2");
                context.block();
                requestsServed++;
                log.info("RequestsServed (H2):"+requestsServed);
                return;
            }
            else {
                //Forward to H3
                //Remember which host is connected to the server
                mappedServerTable.put((Ip4Address) IpAddress.valueOf(ipv4Packet.getSourceAddress()), ethPkt.getSourceMAC());

                forwardRequest(context, MacAddress.valueOf("00:00:00:00:00:03"),ethPkt.getSourceMAC(), 
                IpAddress.valueOf("10.0.0.3"),IpAddress.valueOf(ipv4Packet.getSourceAddress()), 3, selector.build());
                
                log.info("Request will be forwarded to H3");
                context.block();
                requestsServed++;
                log.info("RequestsServed (H3):"+requestsServed);
                return;
            }
        }

        public void forwardRequest(PacketContext context, MacAddress dstMac,MacAddress srcMac, IpAddress dstIp, IpAddress srcIp, int port, TrafficSelector selector) {

            /*
            Specify the Treatment we want on the packets. Since the packets have the LB as the destination,
            we need to change their dstIP and dstMAC to that of the serving server. And then send the packet out.
             */
            TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                    .setEthDst(dstMac)
                    .setIpDst(dstIp)
                    .setOutput(PortNumber.portNumber(port))
                    .build();

            ForwardingObjective forwardingObjective = DefaultForwardingObjective.builder().withTreatment(treatment)
                    .withSelector(selector)
                    .withPriority(100)
                    .withFlag(ForwardingObjective.Flag.VERSATILE)
                    .fromApp(appId)
                    .makeTemporary(10)
                    .add();
            flowObjectiveService.forward(context.inPacket().receivedFrom().deviceId(), forwardingObjective);

            /*
            To simplify the process, install also the return route on the LB.
            Now we need to instruct the LB to change the srcIP and srcMAC from that of the serving server to that of the LB itself.
             */
            TrafficTreatment treatment2 = DefaultTrafficTreatment.builder()
                    .setEthSrc(MacAddress.valueOf("00:00:00:00:00:14"))
                    .setIpSrc(IpAddress.valueOf("10.0.0.100"))
                    .setOutput(PortNumber.portNumber(1))
                    .build();

            TrafficSelector.Builder selectorBuilder = DefaultTrafficSelector.builder();
            selectorBuilder.matchEthType(Ethernet.TYPE_IPV4)
                    .matchIPDst(IpPrefix.valueOf(dstIp, IpPrefix.MAX_INET_MASK_LENGTH))
                    .matchEthDst(dstMac);
                    // .matchIPDst(IpPrefix.valueOf(IpAddress.valueOf("10.0.0.1"), IpPrefix.MAX_INET_MASK_LENGTH))
                    // .matchEthDst(MacAddress.valueOf("00:00:00:00:00:01"));

            ForwardingObjective forwardingObjective2 = DefaultForwardingObjective.builder().withTreatment(treatment2)
                    .withSelector(selectorBuilder.build())
                    .withPriority(100)
                    .withFlag(ForwardingObjective.Flag.VERSATILE)
                    .fromApp(appId)
                    .makeTemporary(10)
                    .add();
            flowObjectiveService.forward(context.inPacket().receivedFrom().deviceId(), forwardingObjective2);
            return;

        }

    }

}