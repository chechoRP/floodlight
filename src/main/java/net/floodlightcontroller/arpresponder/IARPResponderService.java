package net.floodlightcontroller.arpresponder;

import java.util.List;

import org.projectfloodlight.openflow.types.IPv4Address;

import net.floodlightcontroller.core.module.IFloodlightService;

public interface IARPResponderService extends IFloodlightService {
	/**
     * Adds a subnet gateway .
     * @param subnet IPv4 Address of the Subnet. 
     */
    public void addSubnet(IPv4Address subnet);
    
    /**
     * Gets a list of subnets
     */
    public List<String> getSubnets();

}
