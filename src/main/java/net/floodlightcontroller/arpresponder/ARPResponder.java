package net.floodlightcontroller.arpresponder;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ConcurrentHashMap;

import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFPacketOut;
import org.projectfloodlight.openflow.protocol.OFPortDesc;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.OFPort;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.internal.IOFSwitchService;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.Data;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPacket;
import net.floodlightcontroller.restserver.IRestApiService;
import net.floodlightcontroller.routing.IRoutingDecision;
import net.floodlightcontroller.routing.RoutingDecision;

public class ARPResponder implements IFloodlightModule, IOFMessageListener, IARPResponderService {
	/* Event logger*/
	protected static Logger logger;
	/* References to services*/
	protected IFloodlightProviderService floodlightProvider;
	protected IOFSwitchService switchManager;
	protected IRestApiService restApi;
	/* Local data structures*/
	protected ConcurrentMap<DatapathId, ConcurrentMap<IPv4Address, PortMACTuple>> arpTable;
	protected ConcurrentMap<IPv4Address, MacAddress> gateways;

	/* Pending to fix bug for outstanding ARP packets with a TIMER. If
	 * subnets are not installed, the controller basically freaks out.*/
	
	protected class PortMACTuple {
		private OFPort inPort;
		private MacAddress mac;
		
		public PortMACTuple(OFPort inPort, MacAddress mac) {
			this.inPort = inPort;
			this.mac = mac;
		}

		public OFPort getInPort() {
			return inPort;
		}

		public PortMACTuple setInPort(OFPort inPort) {
			this.inPort = inPort;
			return this;
		}

		public MacAddress getMac() {
			return mac;
		}

		public PortMACTuple setMac(MacAddress mac) {
			this.mac = mac;
			return this;
		}

		@Override
		public String toString() {
			return "PortMACTuple [inPort=" + inPort + ", mac=" + mac + "]";
		}
		
		
	}
	
	@Override
	public String getName() {
		return "ARP Responder";
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		return false;
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		return false;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
		l.add(IARPResponderService.class);
		    return l;
	}
	
	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
	    Map<Class<? extends IFloodlightService>, IFloodlightService> m = new HashMap<Class<? extends IFloodlightService>, IFloodlightService>();
	    m.put(IARPResponderService.class, this);
	    return m;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
	    l.add(IFloodlightProviderService.class);
	    l.add(IOFSwitchService.class);
	    l.add(IRestApiService.class);
	    return l;
	}

	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException {
		floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
		switchManager = context.getServiceImpl(IOFSwitchService.class);
		restApi = context.getServiceImpl(IRestApiService.class);
		logger = LoggerFactory.getLogger(ARPResponder.class);
		arpTable = new ConcurrentHashMap<DatapathId,ConcurrentMap<IPv4Address, PortMACTuple>>();
		gateways = new ConcurrentHashMap<IPv4Address, MacAddress>();
		/* This should be added via REST API not hard-coded*/
		//subnets.add(IPv4Address.of("192.168.10.1"));
		//subnets.add(IPv4Address.of("192.168.50.1"));
	}

	@Override
	public void startUp(FloodlightModuleContext context)
			throws FloodlightModuleException {
		if (logger.isInfoEnabled()) {
			logger.info("ARP Responder Module started");
		}
		// We want to handle OF Packet IN messages
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
//		Register our Restlet Routable with the REST API service.
		restApi.addRestletRoutable(new ARPResponderWebRoutable());

	}

	@Override
	public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		switch (msg.getType()) {
    	case PACKET_IN:
    		IRoutingDecision decision = null;
            if (cntx != null) {
                decision = IRoutingDecision.rtStore.get(cntx, IRoutingDecision.CONTEXT_DECISION);
            }
			return this.processPacketInMessage(sw, (OFPacketIn) msg, decision, cntx);
    	default:
    		break;
		}
	return Command.CONTINUE;
	}

	private Command processPacketInMessage(IOFSwitch sw, OFPacketIn msg, 
			IRoutingDecision decision, FloodlightContext cntx) {
		/* Get the Ethernet frame from PACKET_IN message*/
		Ethernet ethPacket = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		// If this is not an ARP message, continue to next module.
		if (ethPacket.getEtherType() != EthType.ARP ){
			return Command.CONTINUE;
		}
		/* Create new ARP packet from Ethernet frame*/
		ARP arp = new ARP();
        arp = (ARP) ethPacket.getPayload();
		// If a decision was previously made, we obey it. 
		if (decision != null) {
			if (logger.isInfoEnabled()) {
                logger.info("Forwaring decision={} was made for PacketIn={}", decision.getRoutingAction().toString(), msg);
            }
	
			switch(decision.getRoutingAction()) {
            	case NONE:
            		// Don't handle the ARP message.
            		return Command.CONTINUE;
            	case DROP:
            		// Don't handle the ARP message.
            		return Command.CONTINUE;
            	case FORWARD_OR_FLOOD:
            		// Handle the ARP message 
            		break;
            	case FORWARD:
            		// Handle the ARP message 
            		break;
            	case MULTICAST:
            		// Handle the ARP message 
            		break;
            	default:
            		logger.error("Unexpected decision made for this packet-in={}", msg, decision.getRoutingAction());
            		return Command.CONTINUE;
			}
		}
		
		// Handle ARP request.
		if (arp.getOpCode() == ARP.OP_REQUEST) {
			return this.handleARPRequest(arp, sw.getId(), msg.getInPort(), cntx);
		}
		
		// Handle ARP reply.
		if (arp.getOpCode() == ARP.OP_REPLY) {
			return this.handleARPReply(arp, sw.getId(), msg.getInPort(), cntx);
		}
		
		// Make a routing decision (NONE) and forward the ARP message to subsequent modules.
		// Actually, this should never happen. However developers are free to develop modules
		// that might modify arp packet headers. 
		decision = new RoutingDecision(sw.getId(), 
				msg.getInPort(), IDeviceService.fcStore.get(cntx, IDeviceService.CONTEXT_SRC_DEVICE), 
				IRoutingDecision.RoutingAction.NONE);
        decision.addToContext(cntx);
		
		return Command.CONTINUE;
	}

	private Command handleARPRequest(ARP arp, DatapathId id, OFPort inPort, 
			FloodlightContext cntx) {
	
		/* The known IP address of the ARP source. */
		IPv4Address sourceIPAddress = arp.getSenderProtocolAddress();
		/* The known MAC address of the ARP source. */
		MacAddress sourceMACAddress = arp.getSenderHardwareAddress();
		/* The target IP address of the ARP Request. */
		IPv4Address targetIPAddress = arp.getTargetProtocolAddress();
		/* The MAC address of the (yet unknown) ARP target. */
		MacAddress targetMACAddress = MacAddress.NONE;
     	// Create tuple with sender's location 
		PortMACTuple tuple = new PortMACTuple(inPort, sourceMACAddress);
		if (!arpTable.containsKey(id)){
			// We know nothing about this switch ... initialize and add host location
			ConcurrentMap<IPv4Address, PortMACTuple> ipToTuple = 
					new ConcurrentHashMap<IPv4Address, PortMACTuple>();
			ipToTuple.put(sourceIPAddress, tuple);
			arpTable.put(id, ipToTuple);
			if (logger.isInfoEnabled()) {
                logger.info("Creating entry for switch {} in ARP Table", id);
            }
		}
		
		if (logger.isInfoEnabled()) {
			logger.info("Received ARP request message from " + 
					sourceMACAddress + 
					" at " + id + " - " 
					+ inPort + " for target: " + targetIPAddress);
//			logger.info("ARP Table " + arpTable);
		}
		
		if (gateways.containsKey(targetIPAddress)){
			// If target IP is in the gateways table. Send ARP Reply with information from that table 
			this.sendARPReply(id, inPort, targetIPAddress, gateways.get(targetIPAddress),
					sourceIPAddress, sourceMACAddress);
			return Command.CONTINUE;
		}

/*
		if (subnets.contains(targetIPAddress)){
			// If the target IP is a Subnet, add Subnet to switch that received ARP, extract 
			// MAC address of inport via SwitchManager and remove address from the subnet list
			arpTable.get(id).put(targetIPAddress, new PortMACTuple(inPort, 
					switchManager.getSwitch(id).getPort(inPort).getHwAddr()));
			subnets.remove(targetIPAddress);
		}
		
*/		
		if (arpTable.get(id).containsKey(targetIPAddress)){
			// If controller knows information of Target IP, send out an ARP Reply
			targetMACAddress = arpTable.get(id).get(targetIPAddress).getMac();
			this.sendARPReply(id, inPort, targetIPAddress, targetMACAddress,
					sourceIPAddress, sourceMACAddress);
		} else {
			// Otherwise, send an ARP request out.
			this.sendARPRequest(id, inPort, sourceIPAddress, sourceMACAddress,
					targetIPAddress, targetMACAddress);
		}
		return Command.CONTINUE;
	}
	
	private net.floodlightcontroller.core.IListener.Command handleARPReply(
			ARP arp, DatapathId id, OFPort inPort, FloodlightContext cntx) {
		return Command.CONTINUE;
	}
	
	/**
	 * Creates an ARP request frame, puts it into a packet out message and 
	 * sends the packet out message to all switch ports (attachment point ports)
	 * that are not connected to other OpenFlow switches.
	 * 
	 * @param arpRequest The ARPRequest object containing information regarding the current ARP process.
	 */
	protected void sendARPRequest(DatapathId id, OFPort inPort, IPv4Address srcIp, 
			MacAddress srcMac, IPv4Address dstIp, MacAddress dstMac) {
		// Create an ARP request frame
		IPacket arpReq = new Ethernet()
    		.setSourceMACAddress(srcMac)
        	.setDestinationMACAddress(MacAddress.BROADCAST)
        	.setEtherType(EthType.ARP)
        	.setPayload(new ARP()
				.setHardwareType(ARP.HW_TYPE_ETHERNET)
				.setProtocolType(ARP.PROTO_TYPE_IP)
				.setOpCode(ARP.OP_REQUEST)
				.setHardwareAddressLength((byte)6)
				.setProtocolAddressLength((byte)4)
				.setSenderHardwareAddress(srcMac)
				.setSenderProtocolAddress(srcIp)
				.setTargetHardwareAddress(dstMac)
				.setTargetProtocolAddress(dstIp)
				.setPayload(new Data(new byte[] {0x01})));
		
		// Send ARP request to all external ports (i.e. attachment point ports).
		for (DatapathId switchId : switchManager.getAllSwitchDpids()) {
			IOFSwitch sw = switchManager.getSwitch(switchId);
			for (OFPortDesc port : sw.getPorts()) {
				OFPort portId = port.getPortNo();
				if (switchId == id && portId == inPort) {
					continue;
				}
					this.sendPOMessage(arpReq, sw, portId);
					if (logger.isInfoEnabled()) {
						logger.info("Send ARP request to " + switchId + " at port " + portId + " \n"+
								arpReq);
					}
			}
		}
	}
	
	
	/**
	 * Creates an ARP reply frame, puts it into a packet out message and 
	 * sends the packet out message to the switch that received the ARP
	 * request message.
	 * 
	 * @param arpRequest The ARPRequest object containing information regarding the current ARP process.
	 */
	protected void sendARPReply(DatapathId id, OFPort inPort, IPv4Address srcIp, MacAddress srcMac,
			IPv4Address dstIp, MacAddress dstMac) {
		// Create an ARP reply frame (from target (source) to source (destination)).
		IPacket arpReply = new Ethernet()
    		.setSourceMACAddress(srcMac)
        	.setDestinationMACAddress(dstMac)
        	.setEtherType(EthType.ARP)
        	.setPayload(new ARP()
				.setHardwareType(ARP.HW_TYPE_ETHERNET)
				.setProtocolType(ARP.PROTO_TYPE_IP)
				.setOpCode(ARP.OP_REPLY)
				.setHardwareAddressLength((byte)6)
				.setProtocolAddressLength((byte)4)
				.setSenderHardwareAddress(srcMac)
				.setSenderProtocolAddress(srcIp)
				.setTargetHardwareAddress(dstMac)
				.setTargetProtocolAddress(dstIp)
				.setPayload(new Data(new byte[] {0x01})));
		// Send ARP reply.
		sendPOMessage(arpReply, switchManager.getSwitch(id), inPort);
		if (logger.isInfoEnabled()) {
			logger.info("Send ARP reply to " + id + " at port " + inPort);
		}
	}
	
	/**
	 * Creates and sends an OpenFlow PacketOut message containing the packet 
	 * information to the switch. The packet included on the PacketOut message 
	 * is sent out at the given port. 
	 * 
	 * @param packet The packet that is sent out.
	 * @param sw The switch that will receive the PacketOut message.
	 * @param port The output port on the switch. 
	 */
	protected void sendPOMessage(IPacket packet, IOFSwitch sw, OFPort port) {		
		// Serialize and wrap in a packet out
        byte[] data = packet.serialize();
        List<OFAction> actions = new ArrayList<OFAction>();
        actions.add(sw.getOFFactory().actions().output(port, 0xffFFffFF)); 
        OFPacketOut po = sw.getOFFactory().buildPacketOut()
        		.setData(data)
        		.setInPort(OFPort.CONTROLLER)
        		.setActions(actions)
        		.build();
      sw.write(po);
	}

	@Override
	public void addGateway(IPv4Address ip, MacAddress mac) {
		this.gateways.put(ip,mac);
		if (logger.isInfoEnabled()) {
			logger.info("Gateway Added via REST: " + ip + " at: " + mac );
		}
	}

	@Override
	public void clearGateways() {
		this.gateways.clear();
		if (logger.isInfoEnabled()) {
			logger.info("Gateways cleared from controller");
		}
	}

	@Override
	public void clearGateway(IPv4Address ip) {
		this.gateways.remove(ip);
		if (logger.isInfoEnabled()) {
			logger.info("Gateway "+ ip.toString() + " removed from controller");
		}
	}
	
	@Override
	public ConcurrentMap<String, String> getGateways() {
		ConcurrentHashMap<String, String> gws = new ConcurrentHashMap<String, String>();
		for (IPv4Address ip: this.gateways.keySet()){
			gws.put(ip.toString(), this.gateways.get(ip).toString());
		}
		return gws;
	}
}

