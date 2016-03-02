package net.floodlightcontroller.arpresponder;

import java.util.concurrent.ConcurrentMap;

import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.MacAddress;

import net.floodlightcontroller.core.module.IFloodlightService;

public interface IARPResponderService extends IFloodlightService {
	/**
     * Adds a subnet gateway .
     * @param subnet IPv4 Address of the Subnet. 
     */
    public void addGateway(IPv4Address ip, MacAddress mac);
    
    /**
     * Returns a list of Gateways
     */
    public ConcurrentMap<String, String> getGateways();
    
    /**
     * Removes all gateways
     */
    public void clearGateways();
    public void clearGateway(IPv4Address ip);

}
